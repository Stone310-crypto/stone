//! Organisationen (Firmen) auf der StoneChain
//!
//! ## Konzept
//!
//! Eine Organisation ist eine Gruppe von Benutzern mit gemeinsamen Dokumenten,
//! Permissions und einem verschlüsselten Chat. Die Daten liegen auf der
//! Blockchain und sind manipulationssicher + durch E2E-Verschlüsselung privat.
//!
//! ## Rollen
//!
//! | Rolle   | Rechte                                                |
//! |---------|-------------------------------------------------------|
//! | owner   | Alle Rechte, kann Organisation löschen, Admins setzen |
//! | admin   | Mitglieder verwalten, Permissions ändern, Chat-Admin  |
//! | member  | Dokumente sehen/hochladen (nach Permission), Chat     |
//! | viewer  | Nur lesen, kein Upload, kein Chat-Schreiben           |
//!
//! ## Permissions für Dokumente
//!
//! Jede Organisation hat Channels (ähnlich wie Ordner), in denen
//! Dokumente und Chat-Nachrichten gruppiert werden können.
//! Permissions werden pro Channel gesetzt.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use crate::blockchain::data_dir;

fn orgs_file() -> String {
    format!("{}/organizations.json", data_dir())
}

// ─── Rollen ──────────────────────────────────────────────────────────────────

/// Rolle eines Mitglieds in einer Organisation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl Default for OrgRole {
    fn default() -> Self {
        OrgRole::Member
    }
}

impl std::fmt::Display for OrgRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrgRole::Owner => write!(f, "owner"),
            OrgRole::Admin => write!(f, "admin"),
            OrgRole::Member => write!(f, "member"),
            OrgRole::Viewer => write!(f, "viewer"),
        }
    }
}

impl OrgRole {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "owner" => OrgRole::Owner,
            "admin" => OrgRole::Admin,
            "viewer" => OrgRole::Viewer,
            _ => OrgRole::Member,
        }
    }

    pub fn can_manage_members(&self) -> bool {
        matches!(self, OrgRole::Owner | OrgRole::Admin)
    }

    pub fn can_upload(&self) -> bool {
        matches!(self, OrgRole::Owner | OrgRole::Admin | OrgRole::Member)
    }

    pub fn can_read(&self) -> bool {
        true // Alle Rollen können lesen
    }

    pub fn can_write_chat(&self) -> bool {
        matches!(self, OrgRole::Owner | OrgRole::Admin | OrgRole::Member)
    }

    pub fn can_delete_org(&self) -> bool {
        matches!(self, OrgRole::Owner)
    }
}

// ─── Mitglied ────────────────────────────────────────────────────────────────

/// Ein Mitglied einer Organisation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrgMember {
    /// User-ID des Mitglieds
    pub user_id: String,
    /// Anzeigename (zum Zeitpunkt des Beitritts)
    pub display_name: String,
    /// Rolle in der Organisation
    pub role: OrgRole,
    /// Unix-Timestamp des Beitritts
    pub joined_at: i64,
    /// Channel-Permissions: Channel-ID → erlaubte Aktionen
    #[serde(default)]
    pub channel_permissions: HashMap<String, ChannelPermission>,
}

// ─── Channel ─────────────────────────────────────────────────────────────────

/// Ein Channel innerhalb einer Organisation (Ordner/Gruppe).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrgChannel {
    pub id: String,
    pub name: String,
    /// "documents", "chat", "both"
    pub channel_type: String,
    pub created_at: i64,
    pub created_by: String,
}

/// Berechtigungen für einen Channel.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelPermission {
    pub read: bool,
    pub write: bool,
    pub upload: bool,
}

impl Default for ChannelPermission {
    fn default() -> Self {
        ChannelPermission {
            read: true,
            write: false,
            upload: false,
        }
    }
}

// ─── Einladung ───────────────────────────────────────────────────────────────

/// Status einer Einladung.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InviteStatus {
    Pending,
    Accepted,
    Declined,
    Expired,
}

/// Einladung in eine Organisation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrgInvite {
    pub invite_id: String,
    pub org_id: String,
    /// User-ID des Eingeladenen
    pub target_user_id: String,
    /// User-ID des Einladenden
    pub invited_by: String,
    /// Vorgeschlagene Rolle
    pub role: OrgRole,
    pub status: InviteStatus,
    pub created_at: i64,
    /// Ablauf: 7 Tage nach Erstellung
    pub expires_at: i64,
}

// ─── Chat-Nachricht ──────────────────────────────────────────────────────────

/// Eine verschlüsselte Chat-Nachricht.
///
/// Nachrichten werden E2E-verschlüsselt gespeichert:
/// - Jede Organisation hat einen Shared Secret (ECDH-abgeleitet)
/// - Der Content ist AES-256-GCM verschlüsselt
/// - Nur Mitglieder mit dem Shared Secret können entschlüsseln
/// - Die Nachricht wird in der Blockchain gespeichert → unveränderlich
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatMessage {
    pub msg_id: String,
    pub org_id: String,
    pub channel_id: String,
    pub sender_id: String,
    pub sender_name: String,
    /// AES-256-GCM verschlüsselter Nachrichtentext (base64)
    pub encrypted_content: String,
    /// AES-256-GCM Nonce (base64, 12 Bytes)
    pub nonce: String,
    /// Unix-Timestamp
    pub timestamp: i64,
    /// Optional: Antwort auf eine andere Nachricht
    #[serde(default)]
    pub reply_to: String,
    /// Gelöscht? (Soft-Delete, Inhalt bleibt verschlüsselt)
    #[serde(default)]
    pub deleted: bool,
}

// ─── Organisation ────────────────────────────────────────────────────────────

/// Eine Organisation (Firma / Gruppe) auf der StoneChain.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Organization {
    /// Einzigartige Organisations-ID (UUID)
    pub id: String,
    /// Anzeigename der Organisation
    pub name: String,
    /// Beschreibung
    #[serde(default)]
    pub description: String,
    /// User-ID des Gründers (Owner)
    pub owner_id: String,
    /// Erstellungszeitpunkt
    pub created_at: i64,
    /// Mitglieder
    pub members: Vec<OrgMember>,
    /// Channels
    pub channels: Vec<OrgChannel>,
    /// Offene Einladungen
    #[serde(default)]
    pub invites: Vec<OrgInvite>,
    /// Chat-Verlauf (verschlüsselt)
    #[serde(default)]
    pub chat_messages: Vec<ChatMessage>,
    /// Verschlüsselungs-Key (AES-256): verschlüsselt mit dem Owner-Wallet-Key
    /// Wird bei Mitglied-Aufnahme per ECDH an das neue Mitglied weitergegeben
    #[serde(default)]
    pub encrypted_org_key: String,
    /// Nonce für den org_key (base64)
    #[serde(default)]
    pub org_key_nonce: String,
}

// ─── Persistenz ──────────────────────────────────────────────────────────────

/// Lädt alle Organisationen aus der Datei.
pub fn load_orgs() -> Vec<Organization> {
    if let Ok(data) = fs::read_to_string(orgs_file()) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Speichert alle Organisationen.
pub fn save_orgs(orgs: &[Organization]) {
    if let Ok(json) = serde_json::to_string_pretty(orgs) {
        let _ = fs::create_dir_all(data_dir());
        let _ = fs::write(orgs_file(), json);
    }
}

// ─── CRUD-Operationen ────────────────────────────────────────────────────────

impl Organization {
    /// Erstellt eine neue Organisation.
    pub fn create(name: &str, description: &str, owner_id: &str, owner_name: &str) -> Self {
        let now = chrono::Utc::now().timestamp();
        let id = format!("org-{}", &uuid::Uuid::new_v4().to_string()[..12]);

        // Standard-Channel "general"
        let general = OrgChannel {
            id: "general".to_string(),
            name: "Allgemein".to_string(),
            channel_type: "both".to_string(),
            created_at: now,
            created_by: owner_id.to_string(),
        };

        let owner_member = OrgMember {
            user_id: owner_id.to_string(),
            display_name: owner_name.to_string(),
            role: OrgRole::Owner,
            joined_at: now,
            channel_permissions: HashMap::from([(
                "general".to_string(),
                ChannelPermission {
                    read: true,
                    write: true,
                    upload: true,
                },
            )]),
        };

        Organization {
            id,
            name: name.to_string(),
            description: description.to_string(),
            owner_id: owner_id.to_string(),
            created_at: now,
            members: vec![owner_member],
            channels: vec![general],
            invites: Vec::new(),
            chat_messages: Vec::new(),
            encrypted_org_key: String::new(),
            org_key_nonce: String::new(),
        }
    }

    /// Prüft ob ein User Mitglied ist.
    pub fn is_member(&self, user_id: &str) -> bool {
        self.members.iter().any(|m| m.user_id == user_id)
    }

    /// Gibt die Rolle eines Users zurück.
    pub fn member_role(&self, user_id: &str) -> Option<&OrgRole> {
        self.members.iter().find(|m| m.user_id == user_id).map(|m| &m.role)
    }

    /// Mitglied hinzufügen.
    pub fn add_member(&mut self, user_id: &str, display_name: &str, role: OrgRole) -> Result<(), String> {
        if self.is_member(user_id) {
            return Err(format!("User {} ist bereits Mitglied", user_id));
        }
        let now = chrono::Utc::now().timestamp();

        // Standardmäßig Leserechte auf alle Channels
        let mut perms = HashMap::new();
        for ch in &self.channels {
            perms.insert(ch.id.clone(), ChannelPermission {
                read: true,
                write: role.can_write_chat(),
                upload: role.can_upload(),
            });
        }

        self.members.push(OrgMember {
            user_id: user_id.to_string(),
            display_name: display_name.to_string(),
            role,
            joined_at: now,
            channel_permissions: perms,
        });
        Ok(())
    }

    /// Mitglied entfernen (Owner kann nicht entfernt werden).
    pub fn remove_member(&mut self, user_id: &str, requester_id: &str) -> Result<(), String> {
        if user_id == self.owner_id {
            return Err("Der Organisation-Owner kann nicht entfernt werden".into());
        }
        let requester_role = self.member_role(requester_id).cloned();
        match requester_role {
            Some(role) if role.can_manage_members() => {}
            Some(_) => return Err("Keine Berechtigung zum Entfernen von Mitgliedern".into()),
            None => return Err("Nicht Mitglied dieser Organisation".into()),
        }
        let before = self.members.len();
        self.members.retain(|m| m.user_id != user_id);
        if self.members.len() == before {
            return Err(format!("User {} ist kein Mitglied", user_id));
        }
        Ok(())
    }

    /// Organisation verlassen (freiwillig).
    pub fn leave(&mut self, user_id: &str) -> Result<(), String> {
        if user_id == self.owner_id {
            return Err("Der Owner kann die Organisation nicht verlassen (erst übertragen)".into());
        }
        let before = self.members.len();
        self.members.retain(|m| m.user_id != user_id);
        if self.members.len() == before {
            return Err("Nicht Mitglied dieser Organisation".into());
        }
        Ok(())
    }

    /// Rolle eines Mitglieds ändern.
    pub fn set_member_role(&mut self, user_id: &str, new_role: OrgRole, requester_id: &str) -> Result<(), String> {
        if user_id == self.owner_id && new_role != OrgRole::Owner {
            return Err("Die Owner-Rolle kann nicht geändert werden".into());
        }
        let requester_role = self.member_role(requester_id).cloned();
        if !matches!(requester_role, Some(OrgRole::Owner | OrgRole::Admin)) {
            return Err("Keine Berechtigung zum Ändern von Rollen".into());
        }
        if let Some(member) = self.members.iter_mut().find(|m| m.user_id == user_id) {
            member.role = new_role;
            Ok(())
        } else {
            Err(format!("User {} ist kein Mitglied", user_id))
        }
    }

    /// Einladung erstellen.
    pub fn invite_user(&mut self, target_user_id: &str, role: OrgRole, invited_by: &str) -> Result<OrgInvite, String> {
        if self.is_member(target_user_id) {
            return Err(format!("User {} ist bereits Mitglied", target_user_id));
        }
        let requester_role = self.member_role(invited_by).cloned();
        if !matches!(requester_role, Some(OrgRole::Owner | OrgRole::Admin)) {
            return Err("Keine Berechtigung zum Einladen".into());
        }
        // Prüfe ob bereits eine offene Einladung existiert
        if self.invites.iter().any(|i| i.target_user_id == target_user_id && i.status == InviteStatus::Pending) {
            return Err(format!("User {} hat bereits eine offene Einladung", target_user_id));
        }
        let now = chrono::Utc::now().timestamp();
        let invite = OrgInvite {
            invite_id: format!("inv-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            org_id: self.id.clone(),
            target_user_id: target_user_id.to_string(),
            invited_by: invited_by.to_string(),
            role,
            status: InviteStatus::Pending,
            created_at: now,
            expires_at: now + 7 * 24 * 3600, // 7 Tage
        };
        self.invites.push(invite.clone());
        Ok(invite)
    }

    /// Einladung annehmen.
    pub fn accept_invite(&mut self, invite_id: &str, user_id: &str, display_name: &str) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp();
        let invite = self.invites.iter_mut()
            .find(|i| i.invite_id == invite_id && i.target_user_id == user_id)
            .ok_or("Einladung nicht gefunden")?;

        if invite.status != InviteStatus::Pending {
            return Err("Einladung ist nicht mehr gültig".into());
        }
        if now > invite.expires_at {
            invite.status = InviteStatus::Expired;
            return Err("Einladung ist abgelaufen".into());
        }

        let role = invite.role.clone();
        invite.status = InviteStatus::Accepted;
        self.add_member(user_id, display_name, role)
    }

    /// Einladung ablehnen.
    pub fn decline_invite(&mut self, invite_id: &str, user_id: &str) -> Result<(), String> {
        let invite = self.invites.iter_mut()
            .find(|i| i.invite_id == invite_id && i.target_user_id == user_id)
            .ok_or("Einladung nicht gefunden")?;
        if invite.status != InviteStatus::Pending {
            return Err("Einladung ist nicht mehr gültig".into());
        }
        invite.status = InviteStatus::Declined;
        Ok(())
    }

    /// Channel erstellen.
    pub fn create_channel(&mut self, name: &str, channel_type: &str, created_by: &str) -> Result<OrgChannel, String> {
        let role = self.member_role(created_by).cloned();
        if !matches!(role, Some(OrgRole::Owner | OrgRole::Admin)) {
            return Err("Keine Berechtigung zum Erstellen von Channels".into());
        }
        let now = chrono::Utc::now().timestamp();
        let id = name.to_lowercase().replace(' ', "-");
        if self.channels.iter().any(|c| c.id == id) {
            return Err(format!("Channel '{}' existiert bereits", id));
        }
        let ch = OrgChannel {
            id: id.clone(),
            name: name.to_string(),
            channel_type: channel_type.to_string(),
            created_at: now,
            created_by: created_by.to_string(),
        };
        self.channels.push(ch.clone());

        // Allen Mitgliedern Standardrechte für den neuen Channel geben
        for m in &mut self.members {
            m.channel_permissions.insert(id.clone(), ChannelPermission {
                read: true,
                write: m.role.can_write_chat(),
                upload: m.role.can_upload(),
            });
        }
        Ok(ch)
    }

    /// Chat-Nachricht hinzufügen.
    pub fn add_chat_message(&mut self, msg: ChatMessage) -> Result<(), String> {
        if !self.is_member(&msg.sender_id) {
            return Err("Nicht Mitglied dieser Organisation".into());
        }
        let role = self.member_role(&msg.sender_id).cloned().unwrap_or_default();
        if !role.can_write_chat() {
            return Err("Keine Berechtigung zum Schreiben im Chat".into());
        }
        // Prüfe Channel-Permission
        if let Some(member) = self.members.iter().find(|m| m.user_id == msg.sender_id) {
            if let Some(perm) = member.channel_permissions.get(&msg.channel_id) {
                if !perm.write {
                    return Err("Keine Schreibrechte in diesem Channel".into());
                }
            }
        }
        self.chat_messages.push(msg);
        Ok(())
    }

    /// Chat-Nachrichten für einen Channel laden (neueste N).
    pub fn chat_history(&self, channel_id: &str, limit: usize) -> Vec<&ChatMessage> {
        let mut msgs: Vec<&ChatMessage> = self.chat_messages.iter()
            .filter(|m| m.channel_id == channel_id && !m.deleted)
            .collect();
        msgs.sort_by_key(|m| m.timestamp);
        if msgs.len() > limit {
            msgs = msgs[msgs.len() - limit..].to_vec();
        }
        msgs
    }
}
