cmake_minimum_required(VERSION 3.20)

project(ftplib)

include_directories(.)

add_library(
        ftplib STATIC
        ftplib.h
        ftplib.cpp
)
