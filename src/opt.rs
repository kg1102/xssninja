use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "xssninja", about = "A tool for XSS scanning")]
pub struct Opt {
    #[structopt(short, long, help = "Path to the file containing URLs")]
    pub file: Option<String>,

    #[structopt(short, long, default_value = "200", help = "Sets the level of concurrency")]
    pub concurrency: usize,

    #[structopt(short, long, help = "Activates verbose mode")]
    pub verbose: bool,
}