//! TUI application state and update logic.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use crate::config;
use crate::model::{Config, Mapping, Protocol};
use crate::probe::ProbeResult;
use crate::{nft, ufw};

/// A form field and how it is edited.
#[derive(Clone, Copy)]
pub enum FieldKind {
    Text,
    Proto,
    Bool,
}

pub struct FieldSpec {
    pub label: &'static str,
    pub kind: FieldKind,
}

pub const FIELDS: &[FieldSpec] = &[
    FieldSpec {
        label: "id",
        kind: FieldKind::Text,
    },
    FieldSpec {
        label: "name",
        kind: FieldKind::Text,
    },
    FieldSpec {
        label: "protocol",
        kind: FieldKind::Proto,
    },
    FieldSpec {
        label: "listen_ip",
        kind: FieldKind::Text,
    },
    FieldSpec {
        label: "listen_port",
        kind: FieldKind::Text,
    },
    FieldSpec {
        label: "target_ip",
        kind: FieldKind::Text,
    },
    FieldSpec {
        label: "target_port",
        kind: FieldKind::Text,
    },
    FieldSpec {
        label: "enabled",
        kind: FieldKind::Bool,
    },
    FieldSpec {
        label: "masquerade",
        kind: FieldKind::Bool,
    },
    FieldSpec {
        label: "description",
        kind: FieldKind::Text,
    },
];

pub struct Form {
    /// `Some(index)` when editing an existing mapping, `None` when adding.
    pub edit_index: Option<usize>,
    pub field: usize,
    pub values: Vec<String>,
}

pub enum Confirm {
    Delete(usize),
    Apply,
}

pub struct App {
    pub config_path: PathBuf,
    pub cfg: Config,
    pub selected: usize,
    pub dirty: bool,
    pub status: String,
    pub form: Option<Form>,
    pub confirm: Option<Confirm>,
    pub show_help: bool,
    pub help_scroll: u16,
    pub should_quit: bool,
    /// Latest probe result per mapping id.
    pub probes: HashMap<String, ProbeResult>,
    /// Mapping ids with an in-flight probe.
    pub probing: HashSet<String>,
    probe_tx: Sender<ProbeResult>,
    probe_rx: Receiver<ProbeResult>,
}

impl App {
    pub fn load(config_path: PathBuf) -> App {
        let (probe_tx, probe_rx) = mpsc::channel();
        let mut app = App {
            config_path,
            cfg: Config::default(),
            selected: 0,
            dirty: false,
            status: String::new(),
            form: None,
            confirm: None,
            show_help: false,
            help_scroll: 0,
            should_quit: false,
            probes: HashMap::new(),
            probing: HashSet::new(),
            probe_tx,
            probe_rx,
        };
        app.reload();
        app
    }

    /// Drain completed probes from the background threads into `probes`.
    pub fn poll_probes(&mut self) {
        while let Ok(r) = self.probe_rx.try_recv() {
            self.probing.remove(&r.mapping_id);
            self.probes.insert(r.mapping_id.clone(), r);
        }
    }

    fn start_probe(&mut self, m: Mapping) {
        self.probing.insert(m.id.clone());
        let tx = self.probe_tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(crate::probe::probe(&m, Duration::from_secs(2)));
        });
    }

    pub fn probe_selected(&mut self) {
        if let Some(m) = self.selected_mapping().cloned() {
            let id = m.id.clone();
            self.start_probe(m);
            self.status = format!("probing {id} …");
        }
    }

    pub fn probe_all(&mut self) {
        let mappings: Vec<Mapping> = self.cfg.mappings.clone();
        let mut n = 0;
        for m in mappings {
            self.start_probe(m);
            n += 1;
        }
        self.status = format!("probing {n} target(s) …");
    }

    pub fn reload(&mut self) {
        match config::load_or_create(&self.config_path) {
            Ok((cfg, _)) => {
                self.cfg = cfg;
                if self.selected >= self.cfg.mappings.len() {
                    self.selected = self.cfg.mappings.len().saturating_sub(1);
                }
                self.dirty = false;
                self.status = "loaded".into();
            }
            Err(e) => self.status = format!("load failed: {e}"),
        }
    }

    pub fn save(&mut self) {
        match config::save(&self.config_path, &self.cfg) {
            Ok(()) => {
                self.dirty = false;
                self.status = "saved".into();
            }
            Err(e) => self.status = format!("save failed: {e}"),
        }
    }

    pub fn apply(&mut self) {
        match nft::apply(&self.cfg) {
            Ok(r) => {
                let mut status = format!(
                    "applied nft (added={}, deleted={}, kept={})",
                    r.added, r.deleted, r.kept
                );
                match ufw::apply(&self.cfg) {
                    Ok(u) if self.cfg.ufw.manage => {
                        status.push_str(&format!(
                            "; ufw (added={}, deleted={}, kept={})",
                            u.added, u.deleted, u.kept
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        self.status = format!("ufw apply failed: {e}");
                        return;
                    }
                }
                self.status = status;
            }
            Err(e) => self.status = format!("apply failed: {e}"),
        }
    }

    pub fn selected_mapping(&self) -> Option<&Mapping> {
        self.cfg.mappings.get(self.selected)
    }

    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn move_down(&mut self) {
        if self.selected + 1 < self.cfg.mappings.len() {
            self.selected += 1;
        }
    }

    pub fn toggle_enabled(&mut self) {
        if let Some(m) = self.cfg.mappings.get_mut(self.selected) {
            m.enabled = !m.enabled;
            self.dirty = true;
            self.status = "enabled toggled — press w to save".into();
        }
    }

    pub fn toggle_masquerade(&mut self) {
        if let Some(m) = self.cfg.mappings.get_mut(self.selected) {
            m.masquerade = !m.masquerade;
            self.dirty = true;
            self.status = "masquerade toggled — press w to save".into();
        }
    }

    pub fn delete_selected(&mut self) {
        if self.selected < self.cfg.mappings.len() {
            let id = self.cfg.mappings.remove(self.selected).id;
            if self.selected >= self.cfg.mappings.len() {
                self.selected = self.cfg.mappings.len().saturating_sub(1);
            }
            self.dirty = true;
            self.status = format!("deleted {id} — press w to save");
        }
    }

    pub fn open_add_form(&mut self) {
        let n = self.cfg.mappings.len() + 1;
        let masq = self.cfg.nftables.default_masquerade.to_string();
        self.form = Some(Form {
            edit_index: None,
            field: 0,
            values: vec![
                format!("rule-{n}"),
                format!("Rule {n}"),
                "tcp".into(),
                "0.0.0.0".into(),
                String::new(),
                String::new(),
                String::new(),
                "true".into(),
                masq,
                String::new(),
            ],
        });
        self.status = "add rule".into();
    }

    pub fn open_edit_form(&mut self) {
        let Some(m) = self.selected_mapping() else {
            return;
        };
        self.form = Some(Form {
            edit_index: Some(self.selected),
            field: 0,
            values: vec![
                m.id.clone(),
                m.name.clone(),
                m.protocol.to_string(),
                m.listen_ip.clone(),
                m.listen_port.to_string(),
                m.target_ip.clone(),
                m.target_port.to_string(),
                m.enabled.to_string(),
                m.masquerade.to_string(),
                m.description.clone(),
            ],
        });
        self.status = "edit rule".into();
    }

    pub fn commit_form(&mut self) {
        let Some(form) = &self.form else { return };
        let m = match mapping_from_values(&form.values) {
            Ok(m) => m,
            Err(e) => {
                self.status = format!("invalid: {e}");
                return;
            }
        };
        let mut next = self.cfg.clone();
        match form.edit_index {
            Some(i) => next.mappings[i] = m,
            None => next.mappings.push(m),
        }
        if let Err(e) = config::validate(&next) {
            self.status = format!("invalid: {e}");
            return;
        }
        let adding = form.edit_index.is_none();
        self.cfg = next;
        if adding {
            self.selected = self.cfg.mappings.len() - 1;
        }
        self.dirty = true;
        self.form = None;
        self.status = "rule updated — press w to save".into();
    }
}

fn mapping_from_values(v: &[String]) -> Result<Mapping, String> {
    let listen_port: u16 = v[4]
        .trim()
        .parse()
        .map_err(|_| "listen_port must be 1-65535")?;
    let target_port: u16 = v[6]
        .trim()
        .parse()
        .map_err(|_| "target_port must be 1-65535")?;
    let protocol: Protocol = v[2].trim().parse()?;
    let enabled: bool = v[7]
        .trim()
        .parse()
        .map_err(|_| "enabled must be true/false")?;
    let masquerade: bool = v[8]
        .trim()
        .parse()
        .map_err(|_| "masquerade must be true/false")?;
    Ok(Mapping {
        id: v[0].trim().to_string(),
        name: v[1].trim().to_string(),
        protocol,
        listen_ip: v[3].trim().to_string(),
        listen_port,
        target_ip: v[5].trim().to_string(),
        target_port,
        enabled,
        masquerade,
        description: v[9].trim().to_string(),
    })
}
