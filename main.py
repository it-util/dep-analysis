#!/usr/bin/env python3
import argparse
import sys
import os
from parse.switchparse import swith_parse
from scanner import scanner
from parse.pdf_parse import create_vulnerability_pdf

def parse_arguments():
    parser = argparse.ArgumentParser(description='Утилита для анализа уязвимостей. Принимает на вход абсолютный путь до файла с зависимостями проекта и производит его анализ на уязвимостей')

    parser.add_argument('--path', '-p', required=True, help='Абсолютный путь до файла с зависимостями')

    return parser.parse_args()

def main():
    args = parse_arguments()

    path = args.path
    
    print(f"Scanning: {path}")

    extension = os.path.splitext(path)[1][1:]

    dependencies = swith_parse[extension](path)

    result = scanner(dependencies)

    create_vulnerability_pdf(result)

    print(result)
    

if __name__ == "__main__":
    sys.exit(main())