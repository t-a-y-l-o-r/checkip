# this module ensures the facory works
#

from collectors import factory, collectors

#            ================
#                Types
#            ================

def test_unique_collector_types():
    record = dict()
    for name, member in factory.Collector_Types.__members__.items():

        already_in = record.get(name)
        if already_in:
            message = "".join([
                "Collector_Types enum must have unique values! ",
                f"Found duplicate name and member: {name}, {member}"
            ])
            raise ValueError(message)

        record[name] = member

def test_collector_factory_construction():
    collector_types = []
    fact = factory.Collector_Factory()

    for col_type in factory.Collector_Types:
        collector_types.append(fact.of(col_type))

    for col in collector_types:
        assert isinstance(col, collectors.Collector)

