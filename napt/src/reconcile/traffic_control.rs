use crate::prelude::network::Interface;
use anyhow::{Context, Result, anyhow};
use futures::stream::{StreamExt, TryStreamExt};
use lbs_core::prelude::{Protocol, Rule};
use netlink_packet_core::{
    DefaultNla, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::tc::TcOption;
use netlink_packet_route::tc::{
    TcAction, TcActionAttribute, TcActionGeneric, TcActionNatOption, TcActionOption, TcActionType,
    TcAttribute, TcFilterU32Option, TcHandle, TcMessage, TcNat, TcNatFlags, TcU32Key,
    TcU32Selector, TcU32SelectorFlags,
};
use rtnetlink::{Handle, new_connection};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tracing::{debug, error, info, warn};

const TC_FILTER_PRIORITY: u16 = 49152; // 0xc000

// Pedit constants (from include/uapi/linux/tc_act/tc_pedit.h)
const TCA_PEDIT_PARMS: u16 = 2;

// Csum constants
const TCA_CSUM_PARMS: u16 = 1;
const TCA_CSUM_F_FLAG_IPV4HDR: u32 = 1 << 0;
const TCA_CSUM_F_FLAG_TCP: u32 = 1 << 3;
const TCA_CSUM_F_FLAG_UDP: u32 = 1 << 4;

// Pedit extended key constants (from include/uapi/linux/tc_act/tc_pedit.h)
const TCA_PEDIT_KEYS_EX: u16 = 5;
const TCA_PEDIT_KEY_EX: u16 = 6;
const TCA_PEDIT_KEY_EX_HTYPE: u16 = 1;
const TCA_PEDIT_KEY_EX_CMD: u16 = 2;

// Header types for pedit extended keys
const PEDIT_HDR_TYPE_TCP: u32 = 4;
const PEDIT_HDR_TYPE_UDP: u32 = 5;
const PEDIT_CMD_SET: u32 = 0;

const NLA_F_NESTED: u16 = 0x8000;

/// Build a raw NLA byte buffer (length + kind + data, 4-byte aligned)
fn build_nla_bytes(kind: u16, data: &[u8]) -> Vec<u8> {
    let len = (4 + data.len()) as u16;
    let mut buf = Vec::with_capacity(((len + 3) & !3) as usize);
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

/// Build TCA_PEDIT_KEY_EX data (one key: htype + cmd) for use as KEYS_EX NLA payload.
/// Returns the raw KEY_EX NLA bytes (with NLA_F_NESTED), to be wrapped by DefaultNla.
fn build_pedit_key_ex_data(htype: u32) -> Vec<u8> {
    let htype_nla = build_nla_bytes(TCA_PEDIT_KEY_EX_HTYPE, &htype.to_ne_bytes());
    let cmd_nla = build_nla_bytes(TCA_PEDIT_KEY_EX_CMD, &PEDIT_CMD_SET.to_ne_bytes());
    let key_ex_inner = [htype_nla, cmd_nla].concat();
    build_nla_bytes(TCA_PEDIT_KEY_EX | NLA_F_NESTED, &key_ex_inner)
}

// Action type values (TC_ACT_*)
const TC_ACT_OK: i32 = 0;
const TC_ACT_PIPE: i32 = 3;

/// U32 filter match criteria
struct U32MatchCriteria {
    protocol: Protocol,
    dsfield_mask: u8,
    dsfield_value: u8,
    src_ip: Ipv4Addr,
    df_flag: bool,
    ihl_mask: u8,
    ihl_value: u8,
    sport: u16,
}

impl U32MatchCriteria {
    /// Convert to TcU32Key instances for netlink
    /// Expected output format:
    /// match 05a80000/0ffc0000 at 0  # Combined version/IHL/DSCP
    /// match <src_ip>/ffffffff at 12
    /// match 00004000/00004000 at 4  # DF flag
    /// match <sport_be>/ffff0000 at 20  # Source port (big-endian)
    fn to_u32_keys(&self) -> Vec<TcU32Key> {
        let mut keys = Vec::new();

        // Combined match: version/IHL (0x05) and DSCP (0xa8) at offset 0
        // Network byte order: 05a80000 with mask 0ffc0000
        keys.push(self.make_match_ihl());

        // Source IP match at offset 12
        keys.push(self.make_match_src_ip());

        // DF flag at offset 4 (fragment offset field, bit 14)
        // Network byte order: 00004000
        keys.push(self.make_match_df());

        // Source port at offset 20, upper 16 bits
        keys.push(self.make_match_sport());

        keys
    }

    // Combined match: version/IHL (0x05) and DSCP (0xa8) at offset 0
    // Network byte order: 05a80000 with mask 0ffc0000
    fn make_match_ihl(&self) -> TcU32Key {
        let mut key = TcU32Key::default();
        key.mask = u32::from_be(0x0ffc0000u32);
        key.val = u32::from_be(0x05a80000u32);
        key.off = 0;
        key
    }

    // Source IP match at offset 12
    fn make_match_src_ip(&self) -> TcU32Key {
        let mut key = TcU32Key::default();
        key.mask = u32::from_be(0xffffffffu32);
        key.val = u32::from_be(u32::from(self.src_ip));
        key.off = 12;
        key
    }

    // DF flag at offset 4 (fragment offset field, bit 14)
    // Network byte order: 00004000
    fn make_match_df(&self) -> TcU32Key {
        let mut key = TcU32Key::default();
        key.mask = u32::from_be(0x00004000u32);
        key.val = u32::from_be(0x00004000u32);
        key.off = 4;
        key
    }

    // Source port at offset 20, upper 16 bits
    fn make_match_sport(&self) -> TcU32Key {
        let mut key = TcU32Key::default();
        key.mask = u32::from_be(0xffff0000u32);
        key.val = u32::from_be((self.sport as u32) << 16);
        key.off = 20;
        key
    }

    /// Build match criteria from a Rule
    fn from_rule(rule: &Rule) -> Result<Self> {
        Ok(Self {
            protocol: rule.protocol,
            dsfield_mask: 0xfc,
            dsfield_value: 0xa8,
            src_ip: rule
                .target
                .address
                .parse::<Ipv4Addr>()
                .context("Invalid target IP address")?,
            df_flag: true,
            ihl_mask: 0x0f,
            ihl_value: 0x05,
            sport: rule.target.port,
        })
    }
}

/// Represents a collection of traffic controlMessage to be applied to a traffic control rule.
pub struct TcMessages {
    messages: Vec<TcMessage>,
}

impl TcMessages {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn push(&mut self, filter: TcMessage) {
        self.messages.push(filter);
    }

    pub fn into_vec(self) -> Vec<TcMessage> {
        self.messages
    }
    pub fn get_filter<'a>(&'a self, rule: &Rule) -> Result<Option<&'a TcMessage>> {
        // Parse address once to avoid ? inside info! macro
        let target_ip: u32 = match rule.target.address.parse::<Ipv4Addr>() {
            Ok(addr) => u32::from(addr),
            Err(_) => return Ok(None),
        };

        for filter in &self.messages {
            for attr in &filter.attributes {
                let opts = match attr {
                    TcAttribute::Options(opts) => opts,
                    _ => continue,
                };
                for opt in opts {
                    let selector = match opt {
                        TcOption::U32(TcFilterU32Option::Selector(selector)) => selector,
                        _ => continue,
                    };
                    if selector_matches_rule(selector, target_ip, rule.target.port) {
                        return Ok(Some(&filter));
                    }
                }
            }
        }
        Ok(None)
    }
}

fn selector_matches_rule(selector: &TcU32Selector, target_ip: u32, target_port: u16) -> bool {
    let df_expected = u32::from_be(0x0000_4000u32);
    let target_ip_expected = u32::from_be(target_ip);
    let sport_expected = u32::from_be((target_port as u32) << 16);

    let mut src_ip_match = false;
    let mut df_match = false;
    let mut sport_match = false;
    for key in &selector.keys {
        if key.off == 12 && key.mask == u32::from_be(0xffff_ffff) {
            src_ip_match = key.val == target_ip_expected;
        } else if key.off == 4 && key.mask == u32::from_be(0x0000_4000) {
            df_match = key.val == df_expected;
        } else if key.off == 20 && key.mask == u32::from_be(0xffff_0000) {
            sport_match = key.val == sport_expected;
        }
    }
    src_ip_match && df_match && sport_match
}

/// Traffic Control (tc) rule manager
pub struct TcManager {
    interface: Interface,
    handle: Handle,
    current_rules: HashSet<Rule>,
    qdisc_initialized: bool,
}

impl TcManager {
    pub fn new(interface: Interface) -> Result<Self> {
        let (connection, handle, _) =
            new_connection().context("Failed to create rtnetlink connection")?;

        tokio::spawn(connection);
        Ok(Self {
            interface,
            handle,
            current_rules: HashSet::new(),
            qdisc_initialized: false,
        })
    }

    pub fn interface_index(&self) -> i32 {
        self.interface.index as i32
    }

    /// Initialize the HTB qdisc on the interface
    async fn ensure_qdisc(&mut self) -> Result<()> {
        if self.qdisc_initialized {
            return Ok(());
        }

        info!(
            "Initializing HTB qdisc on interface {}",
            self.interface.name
        );

        // Check if qdisc already exists
        let mut qdiscs = self
            .handle
            .qdisc()
            .get()
            .index(self.interface_index())
            .execute();

        let mut qdisc_exists = false;
        while let Some(qdisc) = qdiscs
            .try_next()
            .await
            .map_err(|e| anyhow!("Failed to query qdisc: {}", e))?
        {
            if qdisc.header.index == self.interface_index() {
                if let TcAttribute::Kind(kind) = &qdisc.attributes[0] {
                    if kind == "htb" && qdisc.header.handle.major == 1 {
                        debug!("HTB qdisc already exists on {}", self.interface.name);
                        qdisc_exists = true;
                        break;
                    }
                }
            }
        }

        if qdisc_exists {
            self.qdisc_initialized = true;
            return Ok(());
        }

        self.add_htb_qdisc().await?;

        self.qdisc_initialized = true;
        info!(
            "Successfully initialized HTB qdisc on {}",
            self.interface.name
        );
        Ok(())
    }

    async fn add_htb_qdisc(&mut self) -> Result<()> {
        let mut msg = TcMessage::with_index(self.interface_index());
        msg.header.parent = TcHandle::ROOT;
        msg.header.handle = TcHandle { major: 1, minor: 0 };
        msg.header.info = ((1u32) << 16) | (nix::libc::ETH_P_ALL.to_be() as u32);

        msg.attributes.push(TcAttribute::Kind("htb".to_string()));

        // Build tc_htb_glob structure for TCA_HTB_INIT
        let mut init_data = vec![0u8; 20];
        init_data[0..4].copy_from_slice(&3u32.to_ne_bytes());
        init_data[4..8].copy_from_slice(&10u32.to_ne_bytes());
        init_data[8..12].copy_from_slice(&1u32.to_ne_bytes());

        msg.attributes.push(TcAttribute::Options(vec![
            netlink_packet_route::tc::TcOption::Other(DefaultNla::new(
                2, // TCA_HTB_INIT
                init_data,
            )),
        ]));

        let payload = RouteNetlinkMessage::NewQueueDiscipline(msg);
        let mut req = NetlinkMessage::new(
            netlink_packet_core::NetlinkHeader::default(),
            NetlinkPayload::from(payload),
        );
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        let mut response = self
            .handle
            .request(req)
            .context("Failed to send qdisc add request")?;

        while let Some(msg) = response.next().await {
            if let NetlinkPayload::Error(error) = msg.payload {
                if !matches!(error.code, Some(c) if c.get() == -17) {
                    anyhow::bail!("Failed to add HTB qdisc: {}", error);
                }
            }
        }

        Ok(())
    }

    /// Query existing filters using rtnetlink
    async fn list_filters(&self) -> Result<TcMessages> {
        let mut filters = self
            .handle
            .traffic_filter(self.interface_index())
            .get()
            .execute();

        let mut result = TcMessages::new();
        while let Some(filter) = filters.try_next().await? {
            result.push(filter);
        }
        Ok(result)
    }

    /// Build NAT action
    fn build_nat_action(&self, target_ip: &str, vip: &str) -> Result<TcAction> {
        let target_ip_u32: Ipv4Addr = target_ip.parse()?;
        let vip_u32: Ipv4Addr = vip.parse()?;

        let mut generic = TcActionGeneric::default();
        // Use index 1 for all actions in the chain (same index = chained)
        generic.index = 0;
        generic.action = TcActionType::Pipe;

        let mut nat_parms = TcNat::default();
        nat_parms.generic = generic;
        nat_parms.old_addr = target_ip_u32;
        nat_parms.new_addr = vip_u32;
        nat_parms.mask = Ipv4Addr::new(255, 255, 255, 255);
        nat_parms.flags = TcNatFlags::Egress;

        debug!(
            "NAT action: index={}, action={:?}, old_addr={}, new_addr={}",
            nat_parms.generic.index,
            nat_parms.generic.action,
            nat_parms.old_addr,
            nat_parms.new_addr
        );

        let mut action = TcAction::default();
        action.attributes = vec![
            TcActionAttribute::Kind("nat".to_string()),
            TcActionAttribute::Options(vec![TcActionOption::Nat(TcActionNatOption::Parms(
                nat_parms,
            ))]),
        ];

        Ok(action)
    }

    /// Build pedit action to reset DSCP
    /// Expected: action order 2: pedit action pipe keys 1
    ///             key #0  at 0: val 00000000 mask ff00ffff
    fn build_pedit_dscp_action(&self) -> TcAction {
        // Build tc_pedit_sel header (24 bytes)
        // tc_gen (20 bytes) + nkeys (1) + flags (1) + padding (2)
        let mut parms = vec![0u8; 24];

        // tc_gen portion (20 bytes)
        parms[0..4].copy_from_slice(&0u32.to_ne_bytes()); // index 0 = kernel auto-assign
        parms[4..8].copy_from_slice(&0u32.to_ne_bytes()); // capab
        parms[8..12].copy_from_slice(&TC_ACT_PIPE.to_ne_bytes()); // action
        parms[12..16].copy_from_slice(&0i32.to_ne_bytes()); // refcnt
        parms[16..20].copy_from_slice(&0i32.to_ne_bytes()); // bindcnt

        // pedit-specific (4 bytes)
        parms[20] = 1; // nkeys
        parms[21] = 0; // flags
        // bytes 22-23 are padding (implicit)

        // Add tc_pedit_key (24 bytes)
        // key #0: at 0, val 00000000, mask ff00ffff (reset DSCP to 0)
        // Use big-endian for mask/val (packet data), native for offsets
        parms.extend_from_slice(&0xff00ffffu32.to_be_bytes()); // mask (big-endian: ff 00 ff ff)
        parms.extend_from_slice(&0u32.to_be_bytes()); // val (big-endian)
        parms.extend_from_slice(&0u32.to_ne_bytes()); // off (native byte order)
        parms.extend_from_slice(&0u32.to_ne_bytes()); // at (native byte order)
        parms.extend_from_slice(&0u32.to_ne_bytes()); // offmask (native byte order)
        parms.extend_from_slice(&0u32.to_ne_bytes()); // shift (native byte order)

        let mut action = TcAction::default();
        action.attributes = vec![
            TcActionAttribute::Kind("pedit".to_string()),
            TcActionAttribute::Options(vec![TcActionOption::Other(DefaultNla::new(
                TCA_PEDIT_PARMS,
                parms,
            ))]),
        ];

        action
    }

    /// Build pedit action for TCP/UDP source port modification
    /// Uses extended attributes (TCA_PEDIT_KEYS_EX) for proper header type display (tcp+0/udp+0)
    fn build_pedit_sport_action(&self, port: u16, htype: u32) -> TcAction {
        // Build tc_pedit_sel header (24 bytes)
        let mut parms = vec![0u8; 24];

        // tc_gen portion
        parms[0..4].copy_from_slice(&0u32.to_ne_bytes()); // index 0 = kernel auto-assign
        parms[4..8].copy_from_slice(&0u32.to_ne_bytes()); // capab
        parms[8..12].copy_from_slice(&TC_ACT_PIPE.to_ne_bytes()); // action
        parms[12..16].copy_from_slice(&0i32.to_ne_bytes()); // refcnt
        parms[16..20].copy_from_slice(&0i32.to_ne_bytes()); // bindcnt

        // pedit-specific
        parms[20] = 1; // nkeys
        parms[21] = 0; // flags

        // Add tc_pedit_key for port modification
        // off = 0: offset within transport header (htype determines which header)
        parms.extend_from_slice(&0x0000ffffu32.to_be_bytes()); // mask (big-endian: 00 00 ff ff)
        parms.extend_from_slice(&((port as u32) << 16).to_be_bytes()); // val (big-endian: port in upper 16 bits)
        parms.extend_from_slice(&0u32.to_ne_bytes()); // off (0, using extended htype instead of 0x80000000)
        parms.extend_from_slice(&0u32.to_ne_bytes()); // at
        parms.extend_from_slice(&0u32.to_ne_bytes()); // offmask
        parms.extend_from_slice(&0u32.to_ne_bytes()); // shift

        // Build extended keys NLA for proper tcp+0/udp+0 display
        let keys_ex_data = build_pedit_key_ex_data(htype);

        let mut action = TcAction::default();
        action.attributes = vec![
            TcActionAttribute::Kind("pedit".to_string()),
            TcActionAttribute::Options(vec![
                TcActionOption::Other(DefaultNla::new(TCA_PEDIT_PARMS, parms)),
                TcActionOption::Other(DefaultNla::new(
                    TCA_PEDIT_KEYS_EX | NLA_F_NESTED,
                    keys_ex_data,
                )),
            ]),
        ];

        action
    }

    /// Build csum action with Ok (pass) for last action
    /// Expected: action order 5: csum (iph, tcp, udp) action pass
    fn build_csum_action(&self) -> TcAction {
        let flags = TCA_CSUM_F_FLAG_IPV4HDR | TCA_CSUM_F_FLAG_TCP | TCA_CSUM_F_FLAG_UDP;

        // Build tc_csum structure (exactly 24 bytes)
        let mut parms = vec![0u8; 24];

        // tc_gen portion (20 bytes)
        parms[0..4].copy_from_slice(&0u32.to_ne_bytes()); // index 0 = kernel auto-assign
        parms[4..8].copy_from_slice(&0u32.to_ne_bytes()); // capab
        parms[8..12].copy_from_slice(&TC_ACT_OK.to_ne_bytes()); // action (not PIPE)
        parms[12..16].copy_from_slice(&0i32.to_ne_bytes()); // refcnt
        parms[16..20].copy_from_slice(&0i32.to_ne_bytes()); // bindcnt

        // csum-specific (4 bytes)
        parms[20..24].copy_from_slice(&flags.to_ne_bytes()); // update_flags

        let mut action = TcAction::default();
        action.attributes = vec![
            TcActionAttribute::Kind("csum".to_string()),
            TcActionAttribute::Options(vec![TcActionOption::Other(DefaultNla::new(
                TCA_CSUM_PARMS,
                parms,
            ))]),
        ];

        action
    }

    /// Build action chain: NAT → pedit DSCP → pedit TCP sport → pedit UDP sport → csum
    fn build_action_chain(&self, rule: &Rule) -> Result<Vec<TcAction>> {
        let mut actions = Vec::new();

        // Build all actions
        let nat = self.build_nat_action(&rule.target.address, &rule.vip)?;
        let pedit_dscp = self.build_pedit_dscp_action();
        let pedit_tcp_sport = self.build_pedit_sport_action(rule.vip_port, PEDIT_HDR_TYPE_TCP);
        let pedit_udp_sport = self.build_pedit_sport_action(rule.vip_port, PEDIT_HDR_TYPE_UDP);
        let csum = self.build_csum_action();

        // Add all actions to the chain
        actions.push(nat);
        actions.push(pedit_dscp);
        actions.push(pedit_tcp_sport);
        actions.push(pedit_udp_sport);
        actions.push(csum);

        debug!("Total actions in chain: {}", actions.len());
        Ok(actions)
    }

    #[inline]
    fn as_any(rule: &Rule) -> Rule {
        let mut r = rule.clone();
        r.protocol = Protocol::Any;
        r
    }

    /// Add traffic controlfilter rules using netlink
    pub async fn add_rules(&mut self, to_add: &[Rule]) -> Result<()> {
        let all_list = self.list_filters().await?;
        let current_any = self
            .current_rules
            .iter()
            .map(Self::as_any)
            .collect::<HashSet<Rule>>();

        let to_add_rules = to_add
            .iter()
            .map(&Self::as_any)
            .collect::<HashSet<Rule>>()
            .difference(&current_any)
            .cloned()
            .collect::<Vec<Rule>>();

        for rule in to_add_rules {
            match all_list.get_filter(&rule) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(e) = self.add_rule(&rule).await {
                        error!("Failed to add traffic controlrule {}: {}", rule, e);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to query traffic controlfilter for rule {}: {}",
                        rule, e
                    );
                }
            }
        }
        self.current_rules.extend(to_add.iter().cloned());
        Ok(())
    }

    /// Delete a traffic controlfilter rule using netlink
    pub async fn delete_rules(&mut self, rules: &[Rule]) -> Result<()> {
        let all_list = self.list_filters().await?;

        // Collect rules to delete
        let delete_rules_raw: HashSet<&Rule> = rules.iter().collect();
        // Remove any rules that are still present, leaving only those that need to be deleted
        self.current_rules.retain(|r| !delete_rules_raw.contains(r));

        let remaining_any: HashSet<Rule> = self.current_rules.iter().map(Self::as_any).collect();

        let to_delete_any = delete_rules_raw
            .iter()
            .map(|r| Self::as_any(r))
            .filter(|r| !remaining_any.contains(r))
            .collect::<Vec<Rule>>();

        // Delete any rules that are no longer present
        for rule in &to_delete_any {
            match all_list.get_filter(rule) {
                Ok(Some(_)) => {
                    if let Err(e) = self.delete_rule(rule).await {
                        error!("Failed to delete traffic controlrule {}: {}", rule, e);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    error!(
                        "Failed to get traffic controlfilter for rule {}: {}",
                        rule, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Add a traffic controlfilter rule using netlink
    async fn add_rule(&mut self, rule: &Rule) -> Result<()> {
        info!("Adding traffic controlrule: {}", rule);

        // Create match criteria from rule
        let criteria = U32MatchCriteria::from_rule(rule)?;
        let keys = criteria.to_u32_keys();

        // Build action chain
        let mut actions = self.build_action_chain(rule)?;
        info!("Built {} actions for filter", actions.len());

        // Debug: print action details
        for (i, action) in actions.iter_mut().enumerate() {
            // set tab index
            action.tab = (i + 1) as u16;
            if let Some(TcActionAttribute::Kind(kind)) = action.attributes.first() {
                debug!("  Action {}: kind={}, tab={}", i, kind, action.tab);
            }
        }

        // Create u32 selector with keys
        let mut selector = TcU32Selector::default();
        selector.flags = TcU32SelectorFlags::from_bits_truncate(1);
        selector.offshift = 0;
        selector.nkeys = keys.len() as u8;
        selector.offmask = 0;
        selector.off = 0;
        selector.offoff = 0;
        selector.hoff = 0;
        selector.hmask = 0;
        selector.keys = keys;

        // Build u32 filter options
        let u32_options = vec![
            TcFilterU32Option::Selector(selector),
            TcFilterU32Option::Action(actions),
        ];

        info!("Sending filter add request...");

        // Send the filter add request using the rtnetlink API
        self.handle
            .traffic_filter(self.interface_index())
            .add()
            .parent(0x00010000) // parent 1:
            .priority(TC_FILTER_PRIORITY)
            .protocol((nix::libc::ETH_P_IP as u16).to_be())
            .u32(&u32_options)?
            .execute()
            .await
            .map_err(|e| anyhow!("Failed to add traffic controlfilter: {}", e))?;

        debug!("Successfully added traffic controlrule: {}", rule);
        Ok(())
    }

    /// Delete a traffic controlfilter rule using netlink
    async fn delete_rule(&mut self, rule: &Rule) -> Result<()> {
        info!("Deleting traffic controlrule: {}", rule);
        match self.list_filters().await?.get_filter(rule)? {
            Some(filter) => {
                // Delete this specific filter by its handle
                // Delete this specific filter by its handle
                let handle = filter.header.handle;

                // Build delete message
                let mut msg = TcMessage::with_index(self.interface_index());
                msg.header.parent = filter.header.parent;
                msg.header.handle = handle;
                msg.header.info = filter.header.info;
                msg.attributes.push(TcAttribute::Kind("u32".to_string()));

                let payload = RouteNetlinkMessage::DelTrafficFilter(msg);
                let mut req = NetlinkMessage::new(
                    netlink_packet_core::NetlinkHeader::default(),
                    NetlinkPayload::from(payload),
                );
                req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

                let mut response = self
                    .handle
                    .request(req)
                    .context("Failed to send filter del request")?;

                while let Some(msg) = response.next().await {
                    if let NetlinkPayload::Error(error) = msg.payload {
                        if !matches!(error.code, Some(c) if c.get() == -2) {
                            // -ENOENT
                            warn!("Failed to delete filter: {}", error);
                        }
                    }
                }
            }
            None => return Ok(()),
        }

        debug!("Successfully deleted traffic controlrule: {}", rule);
        return Ok(());
    }

    /// Apply a set of rules, adding new ones and removing old ones
    pub async fn apply_rules(&mut self, rules: &[Rule]) -> Result<()> {
        // Ensure qdisc is initialized
        self.ensure_qdisc().await?;

        let new_rules: HashSet<Rule> = rules.iter().cloned().collect();

        // Find rules to add (present in new but not in current)
        let to_add: Vec<_> = new_rules.difference(&self.current_rules).cloned().collect();

        // Find rules to remove (present in current but not in new)
        let to_remove: Vec<_> = self.current_rules.difference(&new_rules).cloned().collect();

        info!(
            "Applying traffic controlrules: {} to add, {} to remove",
            to_add.len(),
            to_remove.len()
        );

        self.add_rules(&to_add).await?;
        self.delete_rules(&to_remove).await?;

        Ok(())
    }

    /// Flush all traffic controlfilters from the qdisc using netlink
    async fn flush_filters(&self) -> Result<()> {
        debug!("Flushing traffic controlfilters on {}", self.interface.name);

        // Delete all filters with parent 1:
        match self
            .handle
            .traffic_filter(self.interface_index())
            .del()
            .execute()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                // Ignore "no such file" errors
                warn!("Failed to flush filters: {}", e);
            }
        }

        Ok(())
    }

    /// Initialize traffic controlrules
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing traffic controlmanager");

        // Ensure qdisc is set up
        self.ensure_qdisc().await?;

        // Start with empty rules
        self.current_rules = HashSet::new();

        Ok(())
    }

    /// Cleanup all managed rules
    pub async fn cleanup(&mut self) -> Result<()> {
        info!("Cleaning up traffic controlrules");

        self.flush_filters().await?;
        self.current_rules.clear();
        self.qdisc_initialized = false;

        info!("traffic controlrules cleaned up done");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lbs_core::prelude::Target;

    #[test]
    fn test_u32_match_criteria_from_rule() {
        let rule = Rule {
            protocol: Protocol::Tcp,
            vip: "172.16.192.111".to_string(),
            vip_port: 888,
            target: Target {
                address: "192.168.2.94".to_string(),
                port: 888,
            },
        };

        let criteria = U32MatchCriteria::from_rule(&rule).unwrap();
        assert_eq!(criteria.dsfield_mask, 0xfc);
        assert_eq!(criteria.dsfield_value, 0xa8);
        assert_eq!(criteria.src_ip, "192.168.2.94".parse::<Ipv4Addr>().unwrap());
        assert_eq!(criteria.sport, 888);
    }

    #[test]
    fn test_u32_match_criteria_to_keys() {
        let rule = Rule {
            protocol: Protocol::Tcp,
            vip: "172.16.192.111".to_string(),
            vip_port: 888,
            target: Target {
                address: "192.168.2.94".to_string(),
                port: 888,
            },
        };

        let criteria = U32MatchCriteria::from_rule(&rule).unwrap();
        let keys = criteria.to_u32_keys();
        assert_eq!(keys.len(), 4); // Combined DSCP/IHL, src IP, DF, sport
    }
}
