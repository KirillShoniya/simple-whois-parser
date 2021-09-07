import gzip

from abc import ABC, abstractmethod
from argparse import ArgumentParser
from datetime import datetime
from io import TextIOWrapper
from typing import Callable
from typing import Generator


class SourceFile:
    def __init__(self, path: str, encoding: str = 'utf-8'):
        self.path: str = path
        self.encoding: str = encoding
        self._file: TextIOWrapper = None

        # Select file open function. Selection depends on: was file gzipped or not
        self._file_open_function: Callable = self._get_file_opener_function()

    def _get_file_opener_function(self) -> Callable:
        """
        Returns file reader which demands on file type: gzipped or not

        :return: function
        """
        if self.is_file_gzipped(self.path):
            return gzip.open
        else:
            return open

    @staticmethod
    def is_file_gzipped(filepath: str) -> bool:
        """
        Return True if file is gzipped.
        Check is based on rule - gzip file starts with two specific bytes: \x1f\x8b

        :param filepath: Absolute path to file
        :return: bool
        """
        with open(filepath, 'rb') as file_source:
            return file_source.read(2) == b'\x1f\x8b'

    def __enter__(self) -> TextIOWrapper:
        """
        Context manager for file reading

        :return: file object
        """
        if self._file is not None:
            raise IOError(f'File is opened already: {self.path}')

        self._file = self._file_open_function(self.path, mode='rt', encoding=self.encoding)

        return self._file

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """ Closes file """
        if not self._file.closed:
            self._file.close()


class IBaseDocument(ABC):
    """ Base document interface """

    @abstractmethod
    def __str__(self) -> str: ...

    @abstractmethod
    def __hash__(self): ...
    """ Just for fun =-) Let's turn any document to hashable entity """


class WhoisDocument(dict, IBaseDocument):
    """ Simple whois document. Represented as dictionary. """

    def join_values(self, join_with: str = '\n') -> None:
        """ Joins arrays in document values to strings """
        for key in self:
            if isinstance(self[key], list):
                self[key] = join_with.join(self[key])

    def __hash__(self):
        return hash(frozenset(self.items()))

    def __str__(self):
        if not self:
            return '{}'

        return '\n' + '\n'.join(f"-- {key}: {self[key]}" for key in self)


class IBaseParser(ABC):
    """ Base parser interface """

    @abstractmethod
    def __iter__(self): ...

    @abstractmethod
    def __next__(self) -> IBaseDocument: ...


class WhoisTextParser(IBaseParser):

    def __init__(
            self,
            file: TextIOWrapper,
            attribute_divider: str = ':',
            document_divider_pattern: str = '\n',
            commentary_symbol: str = '#'
    ):
        self._file = file
        self._attribute_divider = attribute_divider
        self._document_divider_pattern = document_divider_pattern
        self._commentary_symbol = commentary_symbol

        self._lines_processed_counter: int = 0

    def _is_document_divider_found(self, line: str) -> bool:
        """ Search for 'new document' pattern in line """
        return line == self._document_divider_pattern

    def _parse_line(self, line: str) -> tuple:
        """
        Parses line to tuple - attribute name and attribute value

        If attribute is None but value is not None that means
        than value of previous attribute is not ended

        If attribute and value is None it means just new line (empty line)

        :param line: full whois response line
        :return: tuple
        """
        if line == '\n' or line.startswith(self._commentary_symbol):
            # empty line or commentary. There are not any attributes or values
            key, value = None, None

        elif line.startswith(' ') or line.startswith('\t'):
            key, value = None, line

        else:
            key, value = line.split(self._attribute_divider)

        if key:
            key = key.strip()

        if value:
            value = value.strip()

        return key, value

    @property
    def lines_processed(self):
        return self._lines_processed_counter

    def __iter__(self):
        return self

    def __next__(self) -> IBaseDocument:
        """ Main method for parsing """
        document = WhoisDocument()
        last_attribute_name: str = ''

        for line in self._file:
            self._lines_processed_counter += 1

            if self._is_document_divider_found(line):

                if not document:
                    # Document divider found before any document parsed
                    # just go to next line
                    continue

                document.join_values()
                return document

            attribute, value = self._parse_line(line)

            if attribute is None and not last_attribute_name:
                # initial loop step with empty line, just skipping
                continue

            if attribute is not None and value is not None:
                if attribute not in document:
                    document[attribute] = [value]
                else:
                    document[attribute].append(value)
            else:
                if attribute is None and value:
                    # value is part of previous attribute value
                    document[last_attribute_name].append(value)

            last_attribute_name = attribute

        if not document:
            raise StopIteration

        # add last parsed document if it exists
        document.join_values()
        return document


def get_datetime_now() -> str:
    """ Helper function which returns datetime now """
    return str(datetime.utcnow())


def print_with_datetime(message):
    print(f'[{get_datetime_now()}] {message}')


def parse_file(path) -> Generator:
    """ Entrypoint to start parsing """
    with SourceFile(path) as source_file:
        parser = WhoisTextParser(source_file)

        for document in parser:
            yield document

        print_with_datetime(f'Lines processed: {parser.lines_processed}')


def load_data(path):
    """ Entrypoint to process successfully parsed data """
    document_processed_counter = 0
    unique_documents = set()
    parsed_data = parse_file(path)

    for document in parsed_data:
        # load document to database (or do something else)
        if document:
            document_processed_counter += 1

        unique_documents.add(hash(document))

    print_with_datetime(f'Documents processed: {document_processed_counter}')
    print_with_datetime(f'Unique documents: {len(unique_documents)}')


if __name__ == '__main__':
    argument_parser = ArgumentParser()
    argument_parser.add_argument('--path', type=str, help='Absolute path to file')
    args = argument_parser.parse_args()

    try:
        print_with_datetime('Start parsing')
        load_data(args.path)
    except KeyboardInterrupt:
        print_with_datetime('Interrupted by user. Exiting... ')
    finally:
        print_with_datetime('Stopped')
