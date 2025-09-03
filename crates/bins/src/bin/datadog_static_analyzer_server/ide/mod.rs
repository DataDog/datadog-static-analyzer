#![allow(clippy::module_name_repetitions)]

mod configuration_file;
use rocket::Route;

pub fn ide_routes() -> Vec<Route> {
    rocket::routes![
        configuration_file::endpoints::post_ignore_rule,
        configuration_file::endpoints::get_can_onboard,
        configuration_file::endpoints::post_can_onboard_v2,
        configuration_file::endpoints::get_get_rulesets,
        configuration_file::endpoints::post_get_rulesets_v2,
        configuration_file::endpoints::post_add_rulesets,
        configuration_file::endpoints::post_add_rulesets_v2,
    ]
}
