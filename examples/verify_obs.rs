//! Ad-hoc verification: exercise the real observer on this Windows host.
//! Not part of the suite — proves tree_for(pid) returns a real subtree.
fn main() {
    let pid = std::process::id();
    match sentinel::tree_for(pid) {
        Some(tree) => {
            println!("[ok] observed pid {} -> '{}'", tree.pid, tree.name);
            println!("[ok] subtree size = {}", tree.size());
            let mut n = 0;
            tree.walk(&mut |p| {
                n += 1;
                if n <= 6 {
                    println!("   pid {:<7} ppid {:<7} {}", p.pid, p.parent_pid, p.name);
                }
            });
            assert!(tree.size() >= 1);
            println!("[ok] walk visited {} nodes, assertion held", n);
        }
        None => {
            eprintln!("[fail] could not observe own pid {}", pid);
            std::process::exit(1);
        }
    }
    // Also prove host-wide enumeration works.
    let all = sentinel::ProcessTree::all();
    println!("[ok] host forest has {} processes", all.len());
    assert!(all.len() > 1);
    println!("[ok] ad-hoc verification PASSED");
}
