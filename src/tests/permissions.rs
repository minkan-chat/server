use std::collections::HashSet;

use crate::ac::permissions::*;

#[test]
fn test_bitflag_overlapping() {
    let mut permission_map = HashSet::new();
    let perms = &mut permission_map;
    safe_insert(MESSAGE_READ, perms);
    safe_insert(MESSAGE_SEND, perms);
    safe_insert(MESSAGE_EDIT, perms);
    safe_insert(MESSAGE_DELETE, perms);
    safe_insert(MESSAGE_DELETE_OWNED, perms);
    safe_insert(CHANNEL_CREATE, perms);
    safe_insert(CHANNEL_EDIT, perms);
    safe_insert(CHANNEL_DELETE, perms);
    safe_insert(USER_INVITE, perms);
    safe_insert(USER_EDIT, perms);
    safe_insert(USER_DELETE, perms);
    safe_insert(USER_SUSPEND, perms);
    
}

fn safe_insert(input: u64, perms: &mut HashSet<u64>) {
    if !perms.insert(input) {
        panic!("Two or more permissions have the same bitfield values!");
    }
}