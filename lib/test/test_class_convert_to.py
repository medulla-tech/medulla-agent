#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2009 Mandriva, http://www.mandriva.com/
# SPDX-FileCopyrightText: 2018-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Provides test
pip install json2xml
pip install xmltodict
pip install pyyaml
"""
import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import unittest
from datetime import datetime
import json
import base64
import zlib
from utils import convert
from json2xml import json2xml
from json2xml.utils import readfromstring, readfromjson
import xmltodict
import yaml
import json
from collections import OrderedDict

class TestConvert(unittest.TestCase):



    def test_convert_dict_to_json(self):
        input_dict = {'key1': 'value1', 'key2': 'value2'}
        expected_json = '{"key1": "value1", "key2": "value2"}'
        self.assertEqual(convert.convert_dict_to_json(input_dict), expected_json)

        input_not_dict = 'not a dict'
        with self.assertRaises(TypeError):
            convert.convert_dict_to_json(input_not_dict)

    def test_convert_bytes_datetime_to_string(self):
        input_dict = {
            'key1': b'value1',
            'key2': datetime(2023, 5, 30, 10, 30, 0),
            b'key3': 'value3',
            'key4': [b'value4', datetime(2023, 5, 30, 11, 0, 0), 'value5'],
            'key5': None,
            'key6': 'false',
            'key7': 'True'
        }
        expected_result = {
            'key1': 'value1',
            'key2': '2023-05-30 10:30:00',
            'key3': 'value3',
            'key4': ['value4', '2023-05-30 11:00:00', 'value5'],
            'key5': '',
            'key6': False,
            'key7': True
        }
        self.assertEqual(convert.convert_bytes_datetime_to_string(input_dict), expected_result)

    def test_convert_to_bytes(self):
        input_str = 'Hello, World!'
        expected_bytes = b'Hello, World!'
        self.assertEqual(convert.convert_to_bytes(input_str), expected_bytes)
        input_bytes = b'Hello, World!'
        self.assertEqual(convert.convert_to_bytes(input_bytes), input_bytes)
        input_not_bytes_or_str = 123
        with self.assertRaises(TypeError):
            convert.convert_to_bytes(input_not_bytes_or_str)

    def test_compress_and_encode(self):
        input_str = 'Hello, World!'
        expected_result = 'eNrzSM3JyddRCM8vyklRBAAfngRq'
        self.assertEqual(convert.compress_and_encode(input_str), expected_result)


    def test_decompress_and_encode(self):
        input_str = 'eNrzSM3JyddRCM8vyklRBAAfngRq'
        expected_result = 'Hello, World!'
        self.assertEqual(convert.decompress_and_encode(input_str), expected_result)


    def test_convert_datetime_to_string(self):
        input_date = datetime(2023, 5, 30, 10, 30, 0)
        expected_result = '2023-05-30 10:30:00'
        self.assertEqual(convert.convert_datetime_to_string(input_date), expected_result)

        input_not_datetime = 'not a datetime'
        with self.assertRaises(TypeError):
            convert.convert_datetime_to_string(input_not_datetime)


    def test_convert_json_to_xml(self):
        input_json = {
            "person": {
                "name": "John",
                "age": 30,
                "city": "New York"
            }
        }
        expected_xml = """<?xml version="1.0" ?>
<all>
	<person type="dict">
		<name type="str">John</name>
		<age type="int">30</age>
		<city type="str">New York</city>
	</person>
</all>
"""
        self.assertEqual(convert.convert_json_to_xml(input_json), expected_xml)


    def test_convert_dict_to_yaml(self):
        input_dict = {
            'name': 'John',
            'age': 25,
            'city': 'New York'
        }
        expected_yaml = "age: 25\ncity: New York\nname: John\n"

        converted_yaml = convert.convert_dict_to_yaml(input_dict)

        self.assertEqual(converted_yaml, expected_yaml)

    def test_convert_yaml_to_dict(self):
        yaml_data = """
        name: John
        age: 25
        city: New York
        """
        expected_dict = {
            'name': 'John',
            'age': 25,
            'city': 'New York'
        }

        result_dict = convert.convert_yaml_to_dict(yaml_data)

        self.assertEqual(result_dict, expected_dict)

    def test_check_json_conformance(self):
        json_data = '{"name": "John", "age": 25, "city": "New York"}'
        self.assertTrue(convert.check_json_conformance(json_data))

        invalid_json_data = '{"name": "John", "age": 25, "city": "New York"'
        self.assertFalse(convert.check_json_conformance(invalid_json_data))

    def test_check_base64_encoding(self):
        input_string = "SGVsbG8gd29ybGQh"
        self.assertTrue(convert.check_base64_encoding(input_string))

        invalid_input_string = "Hello world!"
        self.assertFalse(convert.check_base64_encoding(invalid_input_string))

    def test_check_yaml_conformance(self):
        yaml_data = """
        name: John
        age: 25
        city: New York
        """
        self.assertTrue(convert.check_yaml_conformance(yaml_data))

        invalid_yaml_data = """
        name: John
        age: 25
        city: New York
        -
        """
        self.assertFalse(convert.check_yaml_conformance(invalid_yaml_data))

    def test_taille_string_in_base64(self):
        string = "Hello world!"
        expected_size = 16
        self.assertEqual(convert.taille_string_in_base64(string), expected_size)



    def test_compare_dicts(self):
        dict1 = {"key1": "value1", "key2": {"nested_key": "nested_value"}}
        dict2 = {"key1": "value1", "key2": {"nested_key": "nested_value"}}
        dict3 = {"key1": "value1", "key2": {"nested_key": "different_value"}}

        self.assertTrue(convert.compare_dicts(dict1, dict2))
        self.assertFalse(convert.compare_dicts(dict1, dict3))

    def test_convert_dict_to_yaml(self):
        input_dict = {"key1": "value1", "key2": "value2"}
        expected_output = "key1: value1\nkey2: value2\n"

        output = convert.convert_dict_to_yaml(input_dict)

        self.assertEqual(output, expected_output)

    def test_convert_yaml_to_dict(self):
        yaml_data = "key1: value1\nkey2: value2\n"
        expected_output = {"key1": "value1", "key2": "value2"}
        output = convert.convert_yaml_to_dict(yaml_data)
        self.assertEqual(output, expected_output)

    def test_yaml_string_to_dict(self):
        yaml_string = "key1: value1\nkey2: value2\n"
        expected_output = {"key1": "value1", "key2": "value2"}
        output = convert.yaml_string_to_dict(yaml_string)
        self.assertEqual(output, expected_output)


    def test_compare_yaml(self):
        yaml_string1 = "key1: value1\nkey2: value2\n"
        yaml_string2 = "key1: value1\nkey2: value2\n"
        yaml_string3 = "key1: value1\nkey2: value3\n"

        self.assertTrue(convert.compare_yaml(yaml_string1, yaml_string2))
        self.assertFalse(convert.compare_yaml(yaml_string1, yaml_string3))

    def test_check_yaml_conformance(self):
        valid_yaml_data = "key1: value1\nkey2: value2\n"
        invalid_yaml_data = "key1: value1\nkey\n2:"
        self.assertTrue(convert.check_yaml_conformance(valid_yaml_data))
        self.assertFalse(convert.check_yaml_conformance(invalid_yaml_data))



    def test_convert_xml_to_dict(self):
        xml_str = """
        <root>
            <person>
                <name>John</name>
                <age>30</age>
            </person>
        </root>
        """
        expected_dict = {
            "root": {
                "person": {
                    "name": "John",
                    "age": "30"
                }
            }
        }
        result_dict = convert.convert_xml_to_dict(xml_str)
        self.assertEqual(result_dict, expected_dict)

    def test_convert_xml_to_json(self):
        xml_str = """
        <root>
            <person>
                <name>John</name>
                <age>30</age>
            </person>
        </root>
        """
        expected_json ="""{
    "root": {
        "person": {
            "name": "John",
            "age": "30"
        }
    }
}"""
        result_json = convert.convert_xml_to_json(xml_str)
        self.assertEqual(result_json, expected_json)

    def test_convert_dict_to_xml(self):
        data_dict = {
            "root": {
                "person": {
                    "name": "John",
                    "age": "30"
                }
            }
        }
        expected_xml = """<?xml version="1.0" encoding="utf-8"?>
<root>
	<root>
		<person>
			<name>John</name>
			<age>30</age>
		</person>
	</root>
</root>"""
        result_xml = convert.convert_dict_to_xml(data_dict)
        self.assertEqual(result_xml, expected_xml)

    def test_compare_xml(self):
        xml_str1 ="""<?xml version="1.0" encoding="utf-8"?>
<root>
	<root>
		<person>
			<name>John</name>
			<age>30</age>
		</person>
	</root>
</root>"""
        xml_str2 ="""<?xml version="1.0" encoding="utf-8"?>
<root>
	<root>
		<person>
			<age>30</age>
			<name>John</name>
		</person>
	</root>
</root>"""
        xml_str3 ="""<?xml version="1.0" encoding="utf-8"?>
<root>
	<root>
		<person>
			<name>John1</name>
			<age>30</age>
		</person>
	</root>
</root>"""
        expected_result = True  # Assuming the XML files are equal
        result = convert.compare_xml(xml_str1, xml_str2)
        self.assertEqual(result, expected_result)
        self.assertTrue( convert.compare_xml(xml_str1, xml_str2))
        self.assertFalse(convert.compare_xml(xml_str1, xml_str3))

    def test_compare_json(self):
        json1 = '{"name": "John", "age": 30}'
        json2 = '{"age": 30, "name": "John"}'
        expected_result = True  # Assuming the JSON objects are equal
        result = convert.compare_json(json1, json2)
        self.assertEqual(result, expected_result)

    def test_string_to_int(self):
        self.assertEqual(convert.string_to_int("123"), 123)
        self.assertEqual(convert.string_to_int("abc"), None)

    def test_int_to_string(self):
        self.assertEqual(convert.int_to_string(123), "123")
        self.assertEqual(convert.int_to_string(-45), "-45")

    def test_string_to_float(self):
        self.assertEqual(convert.string_to_float("3.14"), 3.14)
        self.assertEqual(convert.string_to_float("abc"), None)

    def test_float_to_string(self):
        self.assertEqual(convert.float_to_string(3.14), "3.14")
        self.assertEqual(convert.float_to_string(-2.5), "-2.5")

    def test_list_to_string(self):
        self.assertEqual(convert.list_to_string(["a", "b", "c"]), "a, b, c")
        self.assertEqual(convert.list_to_string(["x", "y", "z"], separator="-"), "x-y-z")

    def test_string_to_list(self):
        self.assertEqual(convert.string_to_list("a, b, c"), ["a", "b", "c"])
        self.assertEqual(convert.string_to_list("x-y-z", separator="-"), ["x", "y", "z"])

    def test_list_to_set(self):
        self.assertEqual(convert.list_to_set(["a", "b", "a", "c"]), {"a", "b", "c"})

    #def test_set_to_list(self):
        #self.assertEqual(convert.set_to_list({"a", "b", "c"}), ["a", "b", "c"])

    def test_dict_to_list(self):
        self.assertEqual(convert.dict_to_list({"a": 1, "b": 2, "c": 3}), [("a", 1), ("b", 2), ("c", 3)])

    def test_list_to_dict(self):
        self.assertEqual(convert.list_to_dict([("a", 1), ("b", 2), ("c", 3)]), {"a": 1, "b": 2, "c": 3})

    def test_char_to_ascii(self):
        self.assertEqual(convert.char_to_ascii("A"), 65)
        self.assertEqual(convert.char_to_ascii("b"), 98)

    def test_ascii_to_char(self):
        self.assertEqual(convert.ascii_to_char(65), "A")
        self.assertEqual(convert.ascii_to_char(98), "b")

    def test_convert_rows_to_columns(self):
        """
            assertCountEqual permet de tester les list de dict ou l'ordre dans des element peut etre different.
            dans notre cas.
            [{'id': [1, 2]}, {'age': [30, 25]}, {'name': ['dede', 'dada']}]
            [{'age': [30, 25]}, {'name': ['dede', 'dada']}, {'id': [1, 2]}]
        """
        data = [
            {"id": 1, "name": "dede", "age": 30},
            {"id": 2, "name": "dada", "age": 25}
        ]
        expected_columns = [
            {'age': [30, 25]},
            {'name': ['dede', 'dada']},
            {'id': [1, 2]}
        ]
        columns = convert.convert_rows_to_columns(data)
        #self.assertEqual(columns, expected_columns)
        self.assertCountEqual(columns, expected_columns)

    def test_convert_columns_to_rows(self):
        data = [{'age': [30, 25]}, {'name': ['dede', 'dada']}, {'id': [1, 2]}]
        expected_output = [{"id": 1, "name": "dede", "age": 30},
                          {"id": 2, "name": "dada", "age": 25}]
        output = convert.convert_columns_to_rows(data)
        self.assertEqual(output, expected_output)


    def test_convert_to_ordered_dict(self):
        # Test case 1
        dict1 = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
        ordered_dict1 = convert.convert_to_ordered_dict(dict1)
        expected1 = OrderedDict([('key1', 'value1'), ('key2', 'value2'), ('key3', 'value3')])
        self.assertEqual(ordered_dict1, expected1)

        # Test case 2
        dict2 = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
        ordered_dict2 = convert.convert_to_ordered_dict(dict2)
        expected2 = OrderedDict([('a', 1), ('b', 2), ('c', 3), ('d', 4)])
        self.assertEqual(ordered_dict2, expected2)

        # Test case 3
        dict3 = {}
        ordered_dict3 = convert.convert_to_ordered_dict(dict3)
        expected3 = OrderedDict()
        self.assertEqual(ordered_dict3, expected3)

if __name__ == '__main__':
    unittest.main()
