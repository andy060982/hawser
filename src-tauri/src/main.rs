// Prevents a console window from appearing alongside the GUI on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    hawser_lib::run()
}
