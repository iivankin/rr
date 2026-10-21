pub fn copy(value: u8) -> u8 {
    // rr: escape(copy): this scalar copy demonstrates a documented snapshot.
    value.clone()
}
// rr: escape(unsafe): the empty function has no caller obligations in this fixture.
pub unsafe fn unchecked() {}
