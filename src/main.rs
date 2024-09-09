#[derive(Debug)]
struct MetaPage {
    lsn: u64,
    pgno: u32,
    magic: u32,
    version: u32,
    pagesize: u32,
    ec: u8,
    ty: u8,
    mf: u8,
    free: u32,
    last_pgno: u32,
    nparts: u32,
    key_count: u32,
    record_count: u32,
    flags: u32,
    uid: [u8; 20],
    minkey: u32,
    re_len: u32,
    re_pad: u32,
    root: u32,
}

impl TryFrom<&[u8]> for MetaPage {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let lsn = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let pgno = u32::from_le_bytes(value[8..12].try_into().unwrap());
        let magic = u32::from_le_bytes(value[12..16].try_into().unwrap());
        let version = u32::from_le_bytes(value[16..20].try_into().unwrap());
        let pagesize = u32::from_le_bytes(value[20..24].try_into().unwrap());
        let ec = value[24];
        let ty = value[25];
        let mf = value[26];
        // empty byte
        let free = u32::from_le_bytes(value[28..32].try_into().unwrap());
        let last_pgno = u32::from_le_bytes(value[32..36].try_into().unwrap());
        let nparts = u32::from_le_bytes(value[36..40].try_into().unwrap());
        let key_count = u32::from_le_bytes(value[40..44].try_into().unwrap());
        let record_count = u32::from_le_bytes(value[44..48].try_into().unwrap());
        let flags = u32::from_le_bytes(value[48..52].try_into().unwrap());
        let uid: [u8; 20] = value[52..72].try_into().unwrap();
        // 4 empty bytes
        let minkey = u32::from_le_bytes(value[76..80].try_into().unwrap());
        let re_len = u32::from_le_bytes(value[80..84].try_into().unwrap());
        let re_pad = u32::from_le_bytes(value[84..88].try_into().unwrap());
        let root = u32::from_le_bytes(value[88..92].try_into().unwrap());

        Ok(MetaPage {
            lsn,
            pgno,
            magic,
            version,
            pagesize,
            ec,
            ty,
            mf,
            free,
            last_pgno,
            nparts,
            key_count,
            record_count,
            flags,
            uid,
            minkey,
            re_len,
            re_pad,
            root,
        })
    }
}

#[derive(Debug)]
struct BTreePageHeader {
    lsn: u64,
    pgno: u32,
    prev_pgno: u32,
    next_pgno: u32,
    entries: u16,
    hf_offset: u16,
    level: u8,
    ty: u8,
}

impl TryFrom<&[u8]> for BTreePageHeader {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let lsn = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let pgno = u32::from_le_bytes(value[8..12].try_into().unwrap());
        let prev_pgno = u32::from_le_bytes(value[12..16].try_into().unwrap());
        let next_pgno = u32::from_le_bytes(value[16..20].try_into().unwrap());
        let entries = u16::from_le_bytes(value[20..22].try_into().unwrap());
        let hf_offset = u16::from_le_bytes(value[22..24].try_into().unwrap());
        let level = value[24];
        let ty = value[25];

        Ok(BTreePageHeader {
            lsn,
            pgno,
            prev_pgno,
            next_pgno,
            entries,
            hf_offset,
            level,
            ty,
        })
    }
}

fn main() {
    let bytes = std::fs::read("testdata.bdb").unwrap();
    let content = bytes.as_slice();
    let meta_page: MetaPage = content[0..512].try_into().unwrap();

    dbg!(&meta_page);
    println!("Magic number: {:#0x}", meta_page.magic);

    for page in content[4096..].chunks(4096) {
        let header: BTreePageHeader = page[0..26].try_into().unwrap();
        dbg!(header);
    }
}
