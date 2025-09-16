cmake_minimum_required(VERSION 3.16)

project(MyProjectAppEdit VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(MYSQL_INCLUDE_DIR "C:/Program Files/MySQL/MySQL Connector C 6.1/include")
set(MYSQL_LIB_DIR "C:/Program Files/MySQL/MySQL Connector C 6.1/lib")
set(VCPKG_INCLUDE_DIR "D:/vcpkg/installed/x64-windows/include")
set(VCPKG_LIB_DIR "D:/vcpkg/installed/x64-windows/lib")
set(OpenSSL_INCLUDE_DIR "D:/Program File/OpenSSL-Win64/include")
set(OpenSSL_LIB_DIR "D:/Program File/OpenSSL-Win64/lib/VC/x64/MT")
set(PKCS11_INCLUDE_DIR "D:/Program File/SoftHSM2/include")
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Pdf)

find_package(Qt6PdfWidgets REQUIRED)
include_directories("${MYSQL_INCLUDE_DIR}")
link_directories("${MYSQL_LIB_DIR}")
include_directories("${VCPKG_INCLUDE_DIR}")
link_directories("${VCPKG_LIB_DIR}")
include_directories("${OpenSSL_INCLUDE_DIR}")
link_directories("${OpenSSL_LIB_DIR}")
include_directories("${PKCS11_INCLUDE_DIR}")

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(MyProjectAppEdit
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        pdfeditor.h pdfeditor.cpp
        resources.qrc
        widgetsConfig/clickablelabel.h widgetsConfig/clickablelabel.cpp
        widgetsConfig/toast.h widgetsConfig/toast.cpp
        Model/hsmconfig.h Model/hsmconfig.cpp
        Model/certificate.h Model/certificate.cpp
        widgetsConfig/pindialog.h widgetsConfig/pindialog.cpp
        widgetsConfig/selectslotdialog.h widgetsConfig/selectslotdialog.cpp
        Model/signature.h Model/signature.cpp

    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET MyProjectAppEdit APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(MyProjectAppEdit SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(MyProjectAppEdit
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(MyProjectAppEdit PRIVATE Qt${QT_VERSION_MAJOR}::Widgets libmysql podofo libssl Qt6::Pdf Qt6::PdfWidgets libssl.lib libcrypto.lib)
# target_link_libraries(MyProjectAppEdit PRIVATE Qt${QT_VERSION_MAJOR}::Widgets libmysql podofo libssl Qt6::Pdf Qt6::PdfWidgets)

target_include_directories(MyProjectAppEdit PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/widgetsConfig
)
# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.MyProjectAppEdit)
endif()
set_target_properties(MyProjectAppEdit PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS MyProjectAppEdit
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(MyProjectAppEdit)
endif()
