//! How a GPU is partitioned for `mig.profile`, as Bottlerocket's nvidia-migmanager does: as many
//! instances of the GPU model's profile as it has room for. A known model (by PCI device ID)
//! takes its own key's profile, or a number of instances; without one, a single instance of the
//! whole GPU. Another MIG GPU tries the profiles of the models the table does not know, in their
//! order, each repeated as its model's memory and the 7 compute slices allow.

use nvidia_controller::GpuModel;
use nvidia_controller::Mig;
use nvidia_controller::MigProfile;

/// A GPU model with MIG.
struct Model {
    /// Its key in `mig.profile`.
    key: &'static str,
    /// Its PCI device IDs.
    device_ids: &'static [u32],
    /// Its profiles, and how many instances of each fill the GPU; the first of a number of
    /// instances is the profile that number stands for.
    profiles: &'static [(&'static str, usize)],
}

/// Bottlerocket's models, with their 4-slice profiles.
const MODELS: [Model; 7] = [
    Model {
        key: "a100.40gb",
        device_ids: &[0x20b0],
        profiles: &[
            ("7g.40gb", 1),
            ("3g.20gb", 2),
            ("2g.10gb", 3),
            ("1g.10gb", 4),
            ("1g.5gb", 7),
            ("4g.20gb", 1),
        ],
    },
    Model {
        key: "a100.80gb",
        device_ids: &[0x20b2, 0x20b5],
        profiles: &[
            ("7g.80gb", 1),
            ("3g.40gb", 2),
            ("2g.20gb", 3),
            ("1g.20gb", 4),
            ("1g.10gb", 7),
            ("4g.40gb", 1),
        ],
    },
    Model {
        key: "h100.80gb",
        device_ids: &[0x2330, 0x2321, 0x2331, 0x2339],
        profiles: &[
            ("7g.80gb", 1),
            ("3g.40gb", 2),
            ("2g.20gb", 3),
            ("1g.20gb", 4),
            ("1g.10gb", 7),
            ("4g.40gb", 1),
        ],
    },
    Model {
        key: "h200.141gb",
        device_ids: &[0x2335, 0x233b, 0x2348],
        profiles: &[
            ("7g.141gb", 1),
            ("3g.71gb", 2),
            ("2g.35gb", 3),
            ("1g.35gb", 4),
            ("1g.18gb", 7),
            ("4g.71gb", 1),
        ],
    },
    Model {
        key: "b200.180gb",
        device_ids: &[0x2901, 0x2941],
        profiles: &[
            ("7g.180gb", 1),
            ("3g.90gb", 2),
            ("2g.45gb", 3),
            ("1g.45gb", 4),
            ("1g.23gb", 7),
            ("4g.90gb", 1),
        ],
    },
    Model {
        key: "b300.269gb",
        device_ids: &[0x3182],
        profiles: &[
            ("7g.269gb", 1),
            ("3g.135gb", 2),
            ("2g.67gb", 3),
            ("1g.67gb", 4),
            ("1g.34gb", 7),
            ("4g.135gb", 1),
        ],
    },
    Model {
        key: "rtxpro6000.96gb",
        device_ids: &[0x2bb5],
        profiles: &[("4g.96gb", 1), ("2g.48gb", 2), ("1g.24gb", 4)],
    },
];

/// The compute slices of a MIG GPU.
const SLICES: u32 = 7;

/// The layouts to try, in order, on the GPU of PCI device `device_id`: the profiles of its
/// instances.
///
/// # Errors
///
/// When the profile of a known model is not one of its profiles.
pub fn layouts(device_id: u32, mig: &Mig) -> Result<Vec<Vec<String>>, String> {
    if let Some(model) = MODELS.iter().find(|m| m.device_ids.contains(&device_id)) {
        let profile = mig
            .profile
            .iter()
            .find(|(key, _)| key.to_string() == model.key)
            .map_or(MigProfile::Instances(1), |(_, profile)| *profile);
        let named = profile.to_string();
        let found = model
            .profiles
            .iter()
            .find(|(name, instances)| match profile {
                MigProfile::Named { .. } => *name == named,
                MigProfile::Instances(n) => *instances == usize::from(n),
            });
        let Some((name, instances)) = found else {
            let profiles: Vec<String> = (model.profiles.iter())
                .map(|(name, instances)| format!("{name} ({instances})"))
                .collect();
            return Err(format!(
                "{profile} is not a MIG profile of {}: {}",
                model.key,
                profiles.join(", ")
            ));
        };
        return Ok(vec![vec![(*name).to_owned(); *instances]]);
    }
    let known = |model: &GpuModel| MODELS.iter().any(|m| model.to_string() == m.key);
    Ok((mig.profile.iter())
        .filter(|(model, _)| !known(model))
        .filter_map(|(model, profile)| {
            let MigProfile::Named { slices, memory_gb } = *profile else {
                return None;
            };
            let instances = (model.memory_gb() / memory_gb).min(SLICES / u32::from(slices));
            let instances = usize::try_from(instances).ok().filter(|n| *n > 0)?;
            Some(vec![profile.to_string(); instances])
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mig(profiles: &[(&str, &str)]) -> Mig {
        Mig {
            profile: (profiles.iter())
                .map(|(model, profile)| {
                    (
                        GpuModel::try_from((*model).to_owned()).unwrap(),
                        MigProfile::try_from((*profile).to_owned()).unwrap(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn a_known_model_by_profile_or_number_of_instances() {
        let a100 = 0x20b0;
        assert_eq!(
            layouts(a100, &mig(&[("a100.40gb", "2g.10gb")])).unwrap(),
            [vec!["2g.10gb"; 3]]
        );
        assert_eq!(
            layouts(a100, &mig(&[("a100.40gb", "7")])).unwrap(),
            [vec!["1g.5gb"; 7]]
        );
        assert_eq!(
            layouts(a100, &mig(&[("a100.40gb", "1")])).unwrap(),
            [vec!["7g.40gb"]]
        );
        assert_eq!(
            layouts(a100, &mig(&[("a100.40gb", "4g.20gb")])).unwrap(),
            [vec!["4g.20gb"]]
        );
        // Another model's profile does not apply.
        assert_eq!(
            layouts(a100, &mig(&[("h100.80gb", "7")])).unwrap(),
            [vec!["7g.40gb"]]
        );
    }

    #[test]
    fn a_wrong_profile_is_an_error() {
        let error = layouts(0x2330, &mig(&[("h100.80gb", "1g.5gb")])).unwrap_err();
        assert!(
            error.starts_with("1g.5gb is not a MIG profile of h100.80gb"),
            "{error}"
        );
        assert!(layouts(0x2bb5, &mig(&[("rtxpro6000.96gb", "7")])).is_err());
    }

    #[test]
    fn another_gpu_tries_the_unknown_models() {
        let layouts = layouts(
            0x1234,
            &mig(&[
                ("a100.40gb", "1g.5gb"),
                ("x200.96gb", "2g.24gb"),
                ("x100.20gb", "1g.10gb"),
                ("x300.40gb", "3"),
            ]),
        )
        .unwrap();
        assert_eq!(layouts, [vec!["1g.10gb"; 2], vec!["2g.24gb"; 3]]);
        assert_eq!(super::layouts(0x1234, &Mig::default()).unwrap().len(), 0);
    }
}
