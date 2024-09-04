/**
 * Dissector for the AXI Stream Packet (axisp) Protocol
 */

#include "config.h"
#include <epan/packet.h>

// Boolean flags in axisp header and tail
typedef enum
{
    axisp_FLAG_SOF = 0x80,
    axisp_FLAG_EOF = 1,
} axisp_flags;

// Protocol handle
static int proto_axisp = -1;

// Handles to header fields
static int hf_axisp_version = -1;
static int hf_axisp_crc_type = -1;
static int hf_axisp_tuser = -1;
static int hf_axisp_channel = -1;
static int hf_axisp_tid = -1;
static int hf_axisp_seq = -1;
static int hf_axisp_header_flags = -1;
static int hf_axisp_sof = -1;

static int hf_axisp_payload = -1;

// Handles to tail fields
static int hf_axisp_tuser_last = -1;
static int hf_axisp_tail_flags = -1;
static int hf_axisp_eof = -1;
static int hf_axisp_last_byte_cnt = -1;
static int hf_axisp_crc = -1;

static gint ett_axisp = -1;

static int
dissect_axisp(tvbuff_t *tvb, packet_info *pInfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pInfo->cinfo, COL_PROTOCOL, "AXISP");
    col_clear(pInfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_axisp, tvb, 0, -1, ENC_NA);
    proto_tree *axisp_tree = proto_item_add_subtree(ti, ett_axisp);

    gint offset = 0;
    
    // CRC Type and Version are contained in the same byte
    guint8 const version_and_crc = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(axisp_tree, hf_axisp_crc_type, tvb, offset, 1, version_and_crc >> 4);
    proto_tree_add_uint(axisp_tree, hf_axisp_version, tvb, offset, 1, version_and_crc & 0xf);
    offset += 1;
    
    proto_tree_add_item(axisp_tree, hf_axisp_tuser, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(axisp_tree, hf_axisp_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(axisp_tree, hf_axisp_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(axisp_tree, hf_axisp_seq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    
    // There is an unused byte here
    offset += 1;

    static int* const header_flags[] =
    {
        &hf_axisp_sof,
        NULL
    };
    
    proto_tree_add_bitmask(axisp_tree, tvb, offset, hf_axisp_header_flags, ett_axisp, header_flags, ENC_LITTLE_ENDIAN);
    offset += 1;
    
    // Now comes the payload, and after that, 8 Bytes of tail
    gint const remaining_len = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_bytes_format(axisp_tree, hf_axisp_payload, tvb, offset, remaining_len - 8, NULL,
    "Payload (%u bytes)", remaining_len - 8);
    
    offset += remaining_len - 8;
    
    proto_tree_add_item(axisp_tree, hf_axisp_tuser_last, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    static int* const tail_flags[] =
    {
        &hf_axisp_eof,
        NULL
    };
    
    proto_tree_add_bitmask(axisp_tree, tvb, offset, hf_axisp_tail_flags, ett_axisp, tail_flags, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(axisp_tree, hf_axisp_last_byte_cnt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(axisp_tree, hf_axisp_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    return tvb_reported_length(tvb);
}

void
proto_register_axisp(void)
{
    static hf_register_info hf[] = {
        {
            &hf_axisp_version,
            {"Version", "axisp.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_crc_type,
            {"CRC type", "axisp.crc_type", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_tuser,
            {"TUser", "axisp.tuser", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_channel,
            {"Channel", "axisp.channel", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_tid,
            {"TId", "axisp.tid", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_seq,
            {"Sequence Number", "axisp.seq", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_header_flags,
            {"Header Flags", "axisp.hflags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_sof,
            {"Start Of File", "axisp.sof", FT_BOOLEAN, 1, NULL, axisp_FLAG_SOF, NULL, HFILL}
        },
        {
            &hf_axisp_payload,
            {"Payload", "axisp.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_tuser_last,
            {"TUser Last", "axisp.tuser_last", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_tail_flags,
            {"Tail Flags", "axisp.tflags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_eof,
            {"End of File", "axisp.eof", FT_BOOLEAN, 1, NULL, axisp_FLAG_EOF, NULL, HFILL}
        },
        {
            &hf_axisp_last_byte_cnt,
            {"Last Byte Count", "axisp.last_byte_cnt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_axisp_crc,
            {"CRC", "axisp.crc", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        }
    };

    static gint *ett[] = {
        &ett_axisp
    };

    proto_axisp = proto_register_protocol("AXI Stream Packet Protocol", "AXISP", "axisp");
    register_dissector("axisp", dissect_axisp, proto_axisp);

    proto_register_field_array(proto_axisp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_axisp(void)
{
    static dissector_handle_t axisp_handle;
    axisp_handle = create_dissector_handle(dissect_axisp, proto_axisp);
}
