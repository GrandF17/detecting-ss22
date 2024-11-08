#ifndef SNIFFER_CONTAINERS_MAP_C_INCLUDED
#define SNIFFER_CONTAINERS_MAP_C_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAP_SIZE 100

typedef struct MapNode {
    char *key;
    void *value;
    struct MapNode *next;
} MapNode;

typedef struct Map {
    MapNode *buckets[MAP_SIZE];
    void (*free_value)(void *);
} Map;

unsigned int hash(const char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash * 31) + *key++;
    }
    return hash % MAP_SIZE;
}

Map *create_map(void (*free_value)(void *)) {
    Map *map = (Map *)malloc(sizeof(Map));
    for (int i = 0; i < MAP_SIZE; i++) {
        map->buckets[i] = NULL;
    }
    map->free_value = free_value;
    return map;
}

void map_insert(Map *map, const char *key, void *value) {
    unsigned int index = hash(key);
    MapNode *node = map->buckets[index];

    // Проверка существующего ключа
    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            if (map->free_value) {
                map->free_value(node->value);  // free last val
            }
            node->value = value;
            return;
        }
        node = node->next;
    }

    node = (MapNode *)malloc(sizeof(MapNode));
    node->key = strdup(key);  // copy of key
    node->value = value;
    node->next = map->buckets[index];
    map->buckets[index] = node;
}

void *map_get(Map *map, const char *key) {
    unsigned int index = hash(key);
    MapNode *node = map->buckets[index];

    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            return node->value;
        }
        node = node->next;
    }

    return NULL;  // key nbot found
}

void map_remove(Map *map, const char *key) {
    unsigned int index = hash(key);
    MapNode *node = map->buckets[index];
    MapNode *prev = NULL;

    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            if (prev == NULL) {
                map->buckets[index] = node->next;
            } else {
                prev->next = node->next;
            }
            free(node->key);
            if (map->free_value) {
                map->free_value(node->value);
            }
            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}

void map_destroy(Map *map) {
    for (int i = 0; i < MAP_SIZE; i++) {
        MapNode *node = map->buckets[i];
        while (node != NULL) {
            MapNode *next = node->next;
            free(node->key);
            if (map->free_value) {
                map->free_value(node->value);
            }
            free(node);
            node = next;
        }
    }
    free(map);
}

#endif