# DemangledStructNaming
IDA 7.7 plugin to improve Create structure from selection naming

Create structure from selection feature works pretty well, but it doesn't care about c++ names when creating VTBL structures. So creating the structure out of:
![image](https://github.com/AntonKukoba1/DemangledStructNaming/assets/35240638/ae12646d-a0d3-4cb9-af9c-7daef5551932)
Generates the structure like this:
![image](https://github.com/AntonKukoba1/DemangledStructNaming/assets/35240638/da239041-71b7-4e54-837d-0c19d1fb5cfc)

This plugin does the demangling stuff when Create structure from selection feature is used and does just-in-time update of the newly created structure. So the result now looks like this:

![image](https://github.com/AntonKukoba1/DemangledStructNaming/assets/35240638/f1802ba2-471b-4dfb-a18c-acf99d8ca2e2)

