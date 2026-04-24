use crate::config::DomainConfig;
use crate::versioning::ConfigRevisionId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionChange {
    InitialLoad {
        to: ConfigRevisionId,
    },
    Unchanged {
        revision: ConfigRevisionId,
    },
    Changed {
        from: ConfigRevisionId,
        to: ConfigRevisionId,
    },
}

pub fn detect_revision_change_from_configs(
    active_config: Option<&DomainConfig>,
    candidate_config: &DomainConfig,
) -> RevisionChange {
    detect_revision_change(
        active_config.map(DomainConfig::revision_id).as_ref(),
        candidate_config,
    )
}

pub fn detect_revision_change(
    active_revision: Option<&ConfigRevisionId>,
    candidate_config: &DomainConfig,
) -> RevisionChange {
    let candidate_revision = candidate_config.revision_id();

    match active_revision {
        None => RevisionChange::InitialLoad {
            to: candidate_revision,
        },
        Some(active) if *active == candidate_revision => RevisionChange::Unchanged {
            revision: candidate_revision,
        },
        Some(active) => RevisionChange::Changed {
            from: active.clone(),
            to: candidate_revision,
        },
    }
}
