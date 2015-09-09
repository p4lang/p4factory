from mapping_common import *

openflow_tables = {
    "dmac": OFTable(
        match_fields = {
            "ingress_metadata_bd": OFMatchField(field="OFPXMT_OFB_VLAN_VID"),
            "l2_metadata_lkp_mac_da"    : OFMatchField(field="OFPXMT_OFB_ETH_DST")
        },

        id = 0
    )
}
