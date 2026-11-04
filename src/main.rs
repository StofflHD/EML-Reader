#![windows_subsystem = "windows"]

mod analysis;
mod app;
mod checks;
mod dkim;
mod domains;
mod files;
mod fonts;
mod htmlcheck;
mod lexicon;
mod mail;
mod msg;
mod online;
mod report;
mod theme;
mod trace;
mod update;

fn main() -> eframe::Result {
    // Files given on the command line (also from the file manager via the desktop file).
    let files: Vec<std::path::PathBuf> = std::env::args_os()
        .skip(1)
        .filter(|a| !a.to_string_lossy().starts_with("--"))
        .map(std::path::PathBuf::from)
        .collect();
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("EML Reader")
        .with_app_id("eml-reader")
        .with_inner_size([980.0, 760.0])
        .with_min_inner_size([560.0, 420.0])
        .with_drag_and_drop(true);
    if let Ok(icon) =
        eframe::icon_data::from_png_bytes(include_bytes!("../packaging/eml-reader.png"))
    {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "EML Reader",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, files)))),
    )
}
