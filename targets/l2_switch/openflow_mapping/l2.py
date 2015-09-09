from mapping_common import *

openflow_tables = {
    "dmac": OFTable(
        match_fields = {
            "ethernet_dstAddr"    : OFMatchField(field="OFPXMT_OFB_ETH_DST")
        },

        id = 0
    )
}
