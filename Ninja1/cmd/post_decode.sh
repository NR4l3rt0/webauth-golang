#!/bin/bash

curl -XPOST -d "[{\"Name\":\"Pete\",\"Age\":15},{\"Name\":\"May\",\"Age\":31}]" http://localhost:8080/decode
