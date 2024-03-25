mod configuration_file;
use rocket::Route;

pub fn ide_routes() -> Vec<Route> {
    rocket::routes![
        configuration_file::endpoints::ignore_rule,
        configuration_file::endpoints::post_rulesets,
        configuration_file::endpoints::get_rulesets
    ]
}
