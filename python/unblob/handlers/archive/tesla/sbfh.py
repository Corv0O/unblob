import binascii
import io
from pathlib import Path

from unblob.file_utils import Endian, FileSystem, InvalidInputFormat, StructParser
from unblob.models import (
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import ExtractionProblem

C_DEFINITIONS = """
    typedef struct sbfh_header {
        char     magic[4];              /* "SBFH" */
        uint32   header_size;
        char     unk[7];
        uint32   firmware_size;
    } sbfh_header_t;

    typedef struct mrvl_header {
        char     magic[4];              /* "MRVL" */
        uint32   unk_const;             /* 0x2E9CF17B */
        uint32   creation_time;
        uint32   num_segments;          /* <= 9 */
        uint32   elf_version;
    } mrvl_header_t;

    typedef struct mrvl_segment_header {
        uint32   segment_type;          /* always 0x2 */
        uint32   offset;                /* relative to MRVL area start */
        uint32   seg_size;
        uint32   virtual_address;
        uint32   crc_checksum;
    } mrvl_segment_header_t;
"""


class SBFHExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            sbfh = self._struct_parser.parse("sbfh_header_t", file, Endian.LITTLE)
            mrvl_offset = sbfh.header_size

            file.seek(mrvl_offset, io.SEEK_SET)
            mrvl = self._struct_parser.cparser_le.mrvl_header_t(file)

            segments = [
                self._struct_parser.cparser_le.mrvl_segment_header_t(file)
                for _ in range(mrvl.num_segments)
            ]
            for seg in segments:
                seg_data = file[
                    mrvl_offset + seg.offset : mrvl_offset + seg.offset + seg.seg_size
                ]
                actual_crc = (binascii.crc32(seg_data, -1) ^ -1) & 0xFFFFFFFF
                if actual_crc != seg.crc_checksum:
                    fs.record_problem(
                        ExtractionProblem(
                            problem=f"CRC mismatch in MRVL segment at vaddr 0x{seg.virtual_address:08x}",
                            resolution="Skipped",
                        )
                    )
                    continue
                fs.carve(
                    Path(f"segment_{seg.virtual_address:08x}.bin"),
                    file,
                    mrvl_offset + seg.offset,
                    seg.seg_size,
                )

        return ExtractResult(reports=fs.problems)


class SBFHHandler(StructHandler):
    NAME = "sbfh"
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "sbfh_header_t"
    PATTERNS = [
        HexString("53 42 46 48"),  # "SBFH"
    ]
    EXTRACTOR = SBFHExtractor()
    DOC = HandlerDoc(
        name="Tesla Wall Connector SBFH",
        description=(
            "SBFH format is used in Tesla Wall Connector firmware, contains also a Marvell MRVL blob of ARM V7 segments "
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Tesla",
        references=[
            Reference(
                title="Tesla Wall Connector Firmware File Structure",
                url="https://akrutsinger.github.io/2023/10/08/tesla-wall-connector-firmware-file-structure.html",
            ),
            Reference(
                title="Marvell 88MW30x Firmware Tools",
                url="https://github.com/wfr/mrvl-88mw30x-firmware-tools",
            ),
            Reference(
                title="Exploiting the Tesla Wall Connector",
                url="https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector.html",
            ),
        ],
        limitations=[],
    )

    def is_valide_sbhf_header(self, sbhf_header) -> bool:
        return sbhf_header.header_size == 0x11C and sbhf_header.firmware_size > 0

    def is_valid_mrvl_header(self, mrvl_header) -> bool:
        return mrvl_header.unk_const == 0x2E9CF17B

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset, io.SEEK_SET)
        header = self.parse_header(file, Endian.LITTLE)

        if not self.is_valide_sbhf_header(header):
            raise InvalidInputFormat("Invalid SBFH header")

        mrvl_offset = start_offset + header.header_size
        file.seek(mrvl_offset, io.SEEK_SET)
        mrvl = self.cparser_le.mrvl_header_t(file)

        if not self.is_valid_mrvl_header(mrvl):
            raise InvalidInputFormat("MRVL not found after SBFH header")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.header_size + header.firmware_size,
        )
