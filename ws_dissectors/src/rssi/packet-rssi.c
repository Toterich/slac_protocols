/**
 * Dissector for the Reliable SLAC Streaming Protocol (RSSI).
 */

#include "config.h"
#include <epan/packet.h>

// Control flags contained in the first byte of the RSSI header
typedef enum
{
    RSSI_FLAG_BUSY = 1,
    RSSI_FLAG_NULL = 1 << 3,
    RSSI_FLAG_RST  = 1 << 4,
    RSSI_FLAG_EAC  = 1 << 5,
    RSSI_FLAG_ACK  = 1 << 6,
    RSSI_FLAG_SYN  = 1 << 7,
} rssi_flags;

// Flags in the Syn packet
typedef enum
{
    RSSI_SYN_FLAG_CHECKSUM = 1 << 2,
} rssi_syn_flags;

// Protocol handle
static int proto_asp = -1;

// Handle to the ASP dissector which dissects this protocol's payload
static dissector_handle_t asp_handle;

// Handles to header fields

// Control bits in first byte
static int hf_rssi_control_flags = -1;
static int hf_rssi_flag_busy = -1;
static int hf_rssi_flag_null = -1;
static int hf_rssi_flag_rst = -1;
static int hf_rssi_flag_eac = -1;
static int hf_rssi_flag_ack = -1;
static int hf_rssi_flag_syn = -1;

// 1 Byte Header length
static int hf_rssi_header_length = -1;
// 1 Byte Sequence number
static int hf_rssi_sequence_number = -1;
// 1 Byte Acknowledgement number
static int hf_rssi_ack_number = -1;
// 2 Byte checksum
static int hf_rssi_checksum = -1;

// Extra fields only for SYN packet

// 4Bit Version
static int hf_rssi_version = -1;

// 4Bit Syn flags
static int hf_rssi_syn_flags = -1;
// Checksum flag
static int hf_rssi_syn_checksum_flag = -1;

// 1 Byte Max Outstanding Segments
static int hf_rssi_max_outstanding_segments = -1;
// 2 Bytes Max Segment Size
static int hf_rssi_max_segment_size = -1;
// 2 Bytes Retransmission timeout
static int hf_rssi_retransmission_timeout = -1;
// 2 Bytes Cumulative Ack timeout
static int hf_rssi_cumulative_ack_timeout = -1;
// 2 Bytes Null timeout
static int hf_rssi_null_timeout = -1;
// 1 Byte Max retransmissions
static int hf_rssi_max_retransmissions = -1;
// 1 Byte Max cumulative acks
static int hf_rssi_max_cumulative_acks = -1;
// 1 Byte Max Out of Sequence acks
static int hf_rssi_max_out_of_seq_ack = -1;
// 1 Byte Timeout unit
static int hf_rssi_timeout_unit = -1;
// 4 Bytes Connection Id
static int hf_rssi_conn_id = -1;

// Extra fields only for Data packet
static int hf_rssi_payload = -1;

static gint ett_asp = -1;

static int
dissect_syn_rssi_packet(tvbuff_t *tvb, proto_tree *tree _U_, gint offset)
{
    static int* const syn_flags[] =
    {
        &hf_rssi_syn_checksum_flag,
        NULL
    };

    // 4 Bits of version info are followed by 4 flag bits
    guint64 flag_int;
    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_rssi_syn_flags, ett_asp, syn_flags, ENC_BIG_ENDIAN, &flag_int);
    proto_tree_add_uint(tree, hf_rssi_version, tvb, offset, 1, (guint32)flag_int >> 4);
    offset += 1;

    proto_tree_add_item(tree, hf_rssi_max_outstanding_segments, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_rssi_max_segment_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_rssi_retransmission_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_rssi_cumulative_ack_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_rssi_null_timeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_rssi_max_retransmissions, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_rssi_max_cumulative_acks, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_rssi_max_out_of_seq_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_rssi_timeout_unit, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_rssi_conn_id, tvb, offset, 4, ENC_BIG_ENDIAN);

    return tvb_reported_length(tvb);
}

static int
dissect_regular_rssi_packet(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    // There are 2 spare bytes after the ack number
    offset += 2;

    proto_tree_add_item(tree, hf_rssi_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // All the remaining bytes in the packet are payload.
    gint const remaining_len = tvb_reported_length_remaining(tvb, offset);

    if (remaining_len > 0)
    {
        proto_tree_add_bytes_format(tree, hf_rssi_payload, tvb, offset, -1, NULL,
        "Payload (%u bytes)", remaining_len);
    }

    // Don't increment offset, as we want to pass the payload to the next dissector
    return offset;
}

static int
dissect_rssi(tvbuff_t *tvb, packet_info *pInfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pInfo->cinfo, COL_PROTOCOL, "RSSI");
    col_clear(pInfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_asp, tvb, 0, -1, ENC_NA);
    proto_tree *rssi_tree = proto_item_add_subtree(ti, ett_asp);

    gint offset = 0;

    static int* const flags[] =
    {
        &hf_rssi_flag_busy,
        &hf_rssi_flag_null,
        &hf_rssi_flag_rst,
        &hf_rssi_flag_eac,
        &hf_rssi_flag_ack,
        &hf_rssi_flag_syn,
        NULL
    };

    guint64 flag_int;
    proto_tree_add_bitmask_ret_uint64(rssi_tree, tvb, offset, hf_rssi_control_flags, ett_asp, flags, ENC_BIG_ENDIAN, &flag_int);
    offset += 1;

    // The format of the remaining header differs between Syn and other packets
    bool const is_syn_packet = flag_int & RSSI_FLAG_SYN;

    guint header_len;
    proto_tree_add_item_ret_uint(rssi_tree, hf_rssi_header_length, tvb, offset, 1, ENC_BIG_ENDIAN, &header_len);
    offset += 1;

    proto_tree_add_item(rssi_tree, hf_rssi_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(rssi_tree, hf_rssi_ack_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (is_syn_packet)
    {
        return dissect_syn_rssi_packet(tvb, rssi_tree, offset);
    }
    else
    {
        offset = dissect_regular_rssi_packet(tvb, rssi_tree, offset);

        // Pass remaining data to ASP dissector
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
        if (tvb_reported_length(next_tvb) > 0)
        {
            return call_dissector(asp_handle, next_tvb, pInfo, tree);
        }
        else
        {
            return tvb_reported_length(tvb);
        }
    }
}

void
proto_register_rssi(void)
{
    static hf_register_info hf[] = {
        {
            &hf_rssi_control_flags,
            {"Control Flags", "rssi.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_flag_busy,
            {"Busy", "rssi.flags.busy", FT_BOOLEAN, 8, NULL, RSSI_FLAG_BUSY, NULL, HFILL}
        },
        {
            &hf_rssi_flag_null,
            {"NULL", "rssi.flags.null", FT_BOOLEAN, 8, NULL, RSSI_FLAG_NULL, NULL, HFILL}
        },
        {
            &hf_rssi_flag_rst,
            {"Reset", "rssi.flags.reset", FT_BOOLEAN, 8, NULL, RSSI_FLAG_RST, NULL, HFILL}
        },
        {
            &hf_rssi_flag_eac,
            {"EAC", "rssi.flags.eac", FT_BOOLEAN, 8, NULL, RSSI_FLAG_EAC, NULL, HFILL}
        },
        {
            &hf_rssi_flag_ack,
            {"ACK", "rssi.flags.ack", FT_BOOLEAN, 8, NULL, RSSI_FLAG_ACK, NULL, HFILL}
        },
        {
            &hf_rssi_flag_syn,
            {"SYN", "rssi.flags.syn", FT_BOOLEAN, 8, NULL, RSSI_FLAG_SYN, NULL, HFILL}
        },
        {
            &hf_rssi_header_length,
            {"Header Length", "rssi.header_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_sequence_number,
            {"Sequence Number", "rssi.seqnum", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_ack_number,
            {"Acknowledgement Number", "rssi.acknum", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_checksum,
            {"Checksum", "rssi.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_version,
            {"Version", "rssi.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_syn_flags,
            {"Syn Flags", "rssi.syn_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_syn_checksum_flag,
            {"Checksum Enabled", "rssi.checksum_flag", FT_BOOLEAN, 4, NULL, RSSI_SYN_FLAG_CHECKSUM, NULL, HFILL}
        },
        {
            &hf_rssi_max_outstanding_segments,
            {"Max outstanding segments", "rssi.max_outstanding_segments", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_max_segment_size,
            {"Max segment size", "rssi.max_segment_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_retransmission_timeout,
            {"Retransmission timeout", "rssi.retransmission_timeout", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_cumulative_ack_timeout,
            {"Ack timeout", "rssi.ack_timeout", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_null_timeout,
            {"Null timeout", "rssi.null_timeout", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_max_retransmissions,
            {"Max retransmissions", "rssi.max_retransmissions", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_max_cumulative_acks,
            {"Max Acks", "rssi.max_acks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_max_out_of_seq_ack,
            {"Max Out of Sequence Acks", "rssi.max_oos_acks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_timeout_unit,
            {"Timeout Unit", "rssi.timeout_unit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_conn_id,
            {"Connection Id", "rssi.conn_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {
            &hf_rssi_payload,
            {"Payload", "rssi.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        }
    };

    static gint *ett[] = {
        &ett_asp
    };

    proto_asp = proto_register_protocol("SLAC RSSI Protocol", "RSSI", "rssi");

    proto_register_field_array(proto_asp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rssi(void)
{
    static dissector_handle_t rssi_handle;
    rssi_handle = create_dissector_handle(dissect_rssi, proto_asp);

    asp_handle = find_dissector("axisp");
}
