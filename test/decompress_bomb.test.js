"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const zlib = require("zlib");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Every public read API funnels through ZipEntry decompress(), and each one used
// to hit the declared-size allocation. Instead of relying on RSS (large zero-filled
// allocations are committed lazily by the OS, so RSS alone can miss them), these
// tests intercept Buffer allocations while the bomb is being read: any request
// above ALLOC_CEILING is refused (so unpatched code fails fast rather than really
// committing gigabytes) and the largest request is asserted to stay bounded.
describe("decompression bomb (declared size) - CVE-2026-39244 - read APIs", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB declared, a few bytes of real data
    const ALLOC_CEILING = 64 * 1024 * 1024;
    const destination = pth.join(os.tmpdir(), "adm-zip-cve-2026-39244-" + process.pid);

    // a valid raw-deflate stream, so the DEFLATED path really inflates before the crc check
    const storedBomb = () => craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A"));
    const deflatedBomb = () => craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.from("A")));

    function guardAllocations() {
        const original = { alloc: Buffer.alloc, allocUnsafe: Buffer.allocUnsafe, allocUnsafeSlow: Buffer.allocUnsafeSlow };
        const state = { largest: 0 };
        const wrap = (fn) =>
            function (size) {
                if (typeof size === "number" && size > state.largest) state.largest = size;
                if (size > ALLOC_CEILING) throw new RangeError("refused allocation of " + size + " bytes");
                return fn.apply(Buffer, arguments);
            };
        Buffer.alloc = wrap(original.alloc);
        Buffer.allocUnsafe = wrap(original.allocUnsafe);
        Buffer.allocUnsafeSlow = wrap(original.allocUnsafeSlow);
        state.restore = () => {
            Buffer.alloc = original.alloc;
            Buffer.allocUnsafe = original.allocUnsafe;
            Buffer.allocUnsafeSlow = original.allocUnsafeSlow;
        };
        return state;
    }

    // runs a synchronous read of the bomb and returns the largest allocation it requested
    function largestSyncAllocation(action) {
        const guard = guardAllocations();
        let error = null;
        try {
            action();
        } catch (err) {
            error = err;
        } finally {
            guard.restore();
        }
        return { largest: guard.largest, error };
    }

    function expectBounded(result) {
        expect(result.largest, "allocation must be bounded by real data, not the declared size").to.be.below(ALLOC_CEILING);
    }

    after(() => rimraf.sync(destination));

    [
        ["STORED", storedBomb],
        ["DEFLATED", deflatedBomb]
    ].forEach(([method, bomb]) => {
        it(`entry.getData() on a ${method} bomb`, () => {
            const zip = new Zip(bomb());
            const result = largestSyncAllocation(() => zip.getEntries()[0].getData());
            expectBounded(result);
            expect(result.error).to.be.an("error");
            expect(result.error.message).to.match(/CRC32/);
        });

        it(`readFile() on a ${method} bomb`, () => {
            const zip = new Zip(bomb());
            const result = largestSyncAllocation(() => zip.readFile("a"));
            expectBounded(result);
            expect(result.error.message).to.match(/CRC32/);
        });

        it(`readAsText() on a ${method} bomb`, () => {
            const zip = new Zip(bomb());
            const result = largestSyncAllocation(() => zip.readAsText("a"));
            expectBounded(result);
            expect(result.error.message).to.match(/CRC32/);
        });

        it(`test() on a ${method} bomb`, () => {
            const zip = new Zip(bomb());
            let ok = true;
            const result = largestSyncAllocation(() => {
                ok = zip.test();
            });
            expectBounded(result);
            expect(ok).to.equal(false);
        });

        it(`extractEntryTo() on a ${method} bomb`, () => {
            const zip = new Zip(bomb());
            const result = largestSyncAllocation(() => zip.extractEntryTo("a", destination, false, true));
            expectBounded(result);
            expect(result.error.message).to.match(/CRC32/);
        });

        it(`extractAllTo() on a ${method} bomb`, () => {
            const zip = new Zip(bomb());
            const result = largestSyncAllocation(() => zip.extractAllTo(destination, true));
            expectBounded(result);
            expect(result.error.message).to.match(/CRC32/);
        });
    });

    it("entry.getDataAsync() on a STORED bomb", () => {
        const zip = new Zip(storedBomb());
        let cbError = null;
        const result = largestSyncAllocation(() =>
            zip.getEntries()[0].getDataAsync((data, err) => {
                cbError = err;
            })
        );
        expectBounded(result);
        expect(String(cbError)).to.match(/CRC32/);
    });

    it("entry.getDataAsync() on a DEFLATED bomb", (done) => {
        const zip = new Zip(deflatedBomb());
        const guard = guardAllocations();
        try {
            zip.getEntries()[0].getDataAsync((data, err) => {
                guard.restore();
                try {
                    expect(guard.largest, "allocation must be bounded by real data, not the declared size").to.be.below(ALLOC_CEILING);
                    expect(String(err)).to.match(/CRC32/);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        } catch (err) {
            guard.restore();
            done(err);
        }
    });

    it("readFileAsync() on a DEFLATED bomb", (done) => {
        const zip = new Zip(deflatedBomb());
        const guard = guardAllocations();
        try {
            zip.readFileAsync("a", (data, err) => {
                guard.restore();
                try {
                    expect(guard.largest, "allocation must be bounded by real data, not the declared size").to.be.below(ALLOC_CEILING);
                    expect(String(err)).to.match(/CRC32/);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        } catch (err) {
            guard.restore();
            done(err);
        }
    });

    it("extractAllToAsync() on a DEFLATED bomb", (done) => {
        const zip = new Zip(deflatedBomb());
        const guard = guardAllocations();
        try {
            zip.extractAllToAsync(destination, true, false, (err) => {
                guard.restore();
                try {
                    expect(guard.largest, "allocation must be bounded by real data, not the declared size").to.be.below(ALLOC_CEILING);
                    expect(String(err)).to.match(/CRC32/);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        } catch (err) {
            guard.restore();
            done(err);
        }
    });
});
