use crate::model::dependency::Dependency;

use crate::model::ecosystem::Ecosystem;

pub trait Analyzer {
    fn get_ecosystem(&self) -> Ecosystem;
    fn get_file_extension(&self) -> String;
    fn parse_file(&self, path: &str) -> anyhow::Result<Vec<Dependency>>;
}
