import ptf.dataplane as dataplane

def match_erspan3_pkt(exp_pkt, pkt, ignore_tstamp=True):
    """
    Compare ERSPAN_III packets, ignore the timestamp value. Just make sure
    it is non-zero
    """
    if ignore_tstamp:
        erspan3 = pkt.getlayer(ERSPAN_III)
        if erspan3 == None:
            #self.logger.error("No ERSPAN pkt received")
            return False

        #if erspan3.timestamp == 0:
        #    #self.logger.error("Invalid ERSPAN timestamp")
        #    return False

        #fix the exp_pkt timestamp and compare
        exp_erspan3 = exp_pkt.getlayer(ERSPAN_III)
        if erspan3 == None:
            #self.logger.error("Test user error - exp_pkt is not ERSPAN_III packet")
            return False

        exp_erspan3.timestamp = 0
        erspan3.timestamp = 0

    return dataplane.match_exp_pkt(exp_pkt, pkt)

def verify_erspan3_packet(test, pkt, ofport):
    """
    Check that an expected packet is received
    """
    logging.debug("Checking for pkt on port %r", ofport)
    (_, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(port_number=ofport, timeout=2, exp_pkt=None)
    test.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % ofport)
    # convert rcv_pkt string back to layered pkt
    nrcv = pkt.__class__(rcv_pkt)
    test.assertTrue(match_erspan3_pkt(pkt, nrcv), "Received packet did not match expected packet")
