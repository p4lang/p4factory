class OFTable():
    def __init__(self, match_fields, id):
        self.match_fields = match_fields
        self.id = id

class OFMatchField():
    def __init__(self, field, match_type="exact", val=None):
        self.field = field
        self.match_type = match_type
        self.testval = val
