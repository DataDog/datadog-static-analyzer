use crate::model::dependency::Dependency;
use anyhow::Context;
use serde_cyclonedx::cyclonedx::v_1_4::CycloneDxBuilder;
use std::fmt::Error;
use std::fs;
use std::io::Write;

fn generate_components(
    dependencies: Vec<Dependency>,
) -> Vec<serde_cyclonedx::cyclonedx::v_1_4::Component> {
    dependencies
        .iter()
        .map(|d| {
            serde_cyclonedx::cyclonedx::v_1_4::ComponentBuilder::default()
                .name(d.name.clone())
                .type_("LIBRARY")
                .version(d.version.clone())
                .purl(d.purl.clone())
                .build()
                .unwrap()
        })
        .collect()
}

pub fn generate_sbom(dependencies: Vec<Dependency>, path: &str) -> anyhow::Result<()> {
    let cyclonedx = CycloneDxBuilder::default()
        .bom_format("CycloneDX")
        .spec_version("1.4")
        .version(1)
        .components(generate_components(dependencies))
        .build()
        .unwrap();

    let mut file = fs::File::create(path).context("cannot create file")?;
    file.write_all(serde_json::to_string(&cyclonedx).unwrap().as_bytes())
        .context("error when writing results")?;
    Ok(())
}
