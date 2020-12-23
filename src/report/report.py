'''
Contains all of the methods and classes
relevent to building and recording information about
specific ip findings

'''

class Report_Builder():
    def __init__(self):
        self.placeholder = "Hello"

    def write_report(self, report, file="./report.json"):
        '''
        Dumps the report in the given file
        '''
        with open(file, "a") as file:
            file.write(report)

    def create_report(self, file="./report.json"):
        '''
        Simple healper method to ensure a file is empty
        '''
        with open(file, "w") as file:
            file.write("")

    def create_record(self, file="./record.json"):
        '''
        Simple helper method to ensure a file is empty
        '''
        with open(file, "w") as file:
            file.write("")

    def write_record(self, record, file="./record.json"):
        '''
        Writes to a "record" which
        will record ips that have already been
        analyzed with the tool

        Args:
            record - the ip information to store
        Time:
            linear - with the amount of information to store
        Space:
            linear - with regard to the amount of information to store
        '''
        with open(file, "w") as file:
            file.write(record)


