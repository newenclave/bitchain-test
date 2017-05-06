TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp

LIBS += -lcrypto

HEADERS += \
    byte_order.h \
    varint.h \
    base58.h \
    hash.h \
    crypto.h \
    serializer.h \
    etool/include/etool/cache/traits/raw.h \
    etool/include/etool/cache/traits/shared.h \
    etool/include/etool/cache/traits/unique.h \
    etool/include/etool/cache/none.h \
    etool/include/etool/cache/shared.h \
    etool/include/etool/cache/simple.h \
    etool/include/etool/details/aligned_buffer.h \
    etool/include/etool/details/byte_order.h \
    etool/include/etool/details/byte_swap.h \
    etool/include/etool/details/dummy_mutex.h \
    etool/include/etool/details/host_byte_order.h \
    etool/include/etool/details/list.h \
    etool/include/etool/details/operators.h \
    etool/include/etool/details/type_uid.h \
    etool/include/etool/dumper/dump.h \
    etool/include/etool/intervals/traits/array_map.h \
    etool/include/etool/intervals/traits/array_set.h \
    etool/include/etool/intervals/traits/std_map.h \
    etool/include/etool/intervals/traits/std_set.h \
    etool/include/etool/intervals/attributes.h \
    etool/include/etool/intervals/endpoint_type.h \
    etool/include/etool/intervals/interval.h \
    etool/include/etool/intervals/map.h \
    etool/include/etool/intervals/set.h \
    etool/include/etool/intervals/tree.h \
    etool/include/etool/logger/interface.h \
    etool/include/etool/logger/simple.h \
    etool/include/etool/observers/traits/simple.h \
    etool/include/etool/observers/base.h \
    etool/include/etool/observers/define.h \
    etool/include/etool/observers/scoped-subscription.h \
    etool/include/etool/observers/simple.h \
    etool/include/etool/observers/subscription.h \
    etool/include/etool/queues/condition/traits/priority.h \
    etool/include/etool/queues/condition/traits/simple.h \
    etool/include/etool/queues/condition/base.h \
    etool/include/etool/sizepack/blockchain_varint.h \
    etool/include/etool/sizepack/fixint.h \
    etool/include/etool/sizepack/none.h \
    etool/include/etool/sizepack/types.h \
    etool/include/etool/sizepack/varint.h \
    etool/include/etool/sizepack/zigzag.h \
    etool/include/etool/slices/container.h \
    etool/include/etool/slices/memory.h \
    etool/include/etool/trees/trie/nodes/array.h \
    etool/include/etool/trees/trie/nodes/map.h \
    etool/include/etool/trees/trie/base.h \
    parser.h

INCLUDEPATH += etool/include

DISTFILES += \
    test.py
