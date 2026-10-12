/*
 * dtbpatch - Apple DeviceTree (iOS flat DT) patcher
 *
 * Patches a raw DeviceTree blob (the decrypted DeviceTree.img3 payload)
 * according to a plain-text operation file. Implements the same node/
 * property semantics as Project5C's tree patcher:
 *
 *   node   := u32 nprops, u32 nchildren            (little-endian)
 *   prop   := char name[32], u32 (flags<<31|len), u8 value[len]
 *             value padded with zeros to a 4-byte boundary
 *   children immediately follow properties, recursively
 *   node path = "/" + name property of root, then "/<child name>"
 *   duplicate sibling names get a 0-based "[k]" ordinal suffix
 *
 * Operation file directives (one per line, '#' comments allowed):
 *   INSERTNODE <parent-path> <child-index> <new-path>
 *   NODEPROPN <name> <flags> <hex-value|->   (defines the inserted node)
 *   ENDNODE
 *   PROPOP <node-path> <prop-name> <insert-index> <flags> <hex|->|DELETE
 *   ACCEPTED <hex|->                        (0..N lines after PROPOP;
 *                                            "-" = property may be absent)
 *   ORDER <node-path> <prop-name> ...       (stable reorder)
 *
 * Build:  cc -O2 -o dtbpatch dtbpatch.c
 * Usage:  dtbpatch <in.dtb> <patch-file> <out.dtb>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct Prop {
    char    name[32];
    uint32_t flags;
    uint8_t *val;
    uint32_t len;
} Prop;

typedef struct Node {
    Prop *props;   int nprops,   capprops;
    struct Node **children; int nchildren, capchildren;
    char name[64];
} Node;

static void die(const char *fmt, const char *a, const char *b) {
    fprintf(stderr, "dtbpatch: error: ");
    fprintf(stderr, fmt, a, b);
    fprintf(stderr, "\n");
    exit(1);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}

/* ---------------- tree parsing ---------------- */

static Node *parse_node(const uint8_t *buf, size_t len, size_t *pos, int depth) {
    if (depth > 64) die("device tree nesting too deep%s%s", "", "");
    if (*pos + 8 > len) die("truncated device tree node%s%s", "", "");
    uint32_t np = rd32(buf + *pos), nc = rd32(buf + *pos + 4);
    *pos += 8;
    if (np > 8192 || nc > 8192) die("implausible device tree counts%s%s", "", "");

    Node *n = calloc(1, sizeof(Node));
    n->capprops = np; n->props = calloc(np ? np : 1, sizeof(Prop));
    n->capchildren = nc; n->children = calloc(nc ? nc : 1, sizeof(Node *));

    for (uint32_t i = 0; i < np; i++) {
        if (*pos + 36 > len) die("truncated property%s%s", "", "");
        Prop *pr = &n->props[n->nprops++];
        memcpy(pr->name, buf + *pos, 32);
        pr->name[31] = 0;
        uint32_t raw = rd32(buf + *pos + 32);
        *pos += 36;
        pr->flags = raw & 0x80000000u;
        pr->len = raw & 0x7fffffffu;
        if (*pos + pr->len > len) die("property value outside tree: %s%s", pr->name, "");
        pr->val = malloc(pr->len ? pr->len : 1);
        memcpy(pr->val, buf + *pos, pr->len);
        *pos += (pr->len + 3u) & ~3u;
        if (strcmp(pr->name, "name") == 0) {
            size_t k = pr->len < 63 ? pr->len : 63;
            memcpy(n->name, pr->val, k);
            n->name[k] = 0;
            char *z = memchr(n->name, 0, k);
            if (z) *z = 0;
        }
    }
    for (uint32_t i = 0; i < nc; i++)
        n->children[n->nchildren++] = parse_node(buf, len, pos, depth + 1);
    return n;
}

static Node *load_tree(const uint8_t *buf, size_t len) {
    size_t pos = 0;
    Node *root = parse_node(buf, len, &pos, 0);
    while (pos < len && buf[pos] == 0) pos++;
    if (pos != len) die("trailing device tree data after offset %zu%s", "", "");
    return root;
}

/* ---------------- path lookup ---------------- */

static Node *find_node(Node *root, const char *path) {
    if (!path || path[0] != '/') return NULL;
    char tmp[512];
    strncpy(tmp, path + 1, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    Node *cur = root;
    char *save = NULL;
    int first = 1;
    for (char *tok = strtok_r(tmp, "/", &save); tok; tok = strtok_r(NULL, "/", &save), first = 0) {
        /* the first path component names the root itself */
        if (first) {
            if (strcmp(tok, root->name) != 0) return NULL;
            continue;
        }
        char base[64];
        int ordinal = 0;
        char *br = strchr(tok, '[');
        if (br) {
            size_t bl = (size_t)(br - tok);
            if (bl >= sizeof(base)) bl = sizeof(base) - 1;
            memcpy(base, tok, bl); base[bl] = 0;
            ordinal = atoi(br + 1);
        } else {
            strncpy(base, tok, sizeof(base) - 1);
            base[sizeof(base) - 1] = 0;
        }
        int seen = 0;
        Node *match = NULL;
        for (int i = 0; i < cur->nchildren; i++) {
            if (strcmp(cur->children[i]->name, base) == 0) {
                if (seen == ordinal) { match = cur->children[i]; break; }
                seen++;
            }
        }
        if (!match) return NULL;
        cur = match;
    }
    return cur;
}

static Prop *find_prop(Node *n, const char *name) {
    for (int i = 0; i < n->nprops; i++)
        if (strcmp(n->props[i].name, name) == 0) return &n->props[i];
    return NULL;
}

static void remove_prop(Node *n, Prop *p) {
    int idx = (int)(p - n->props);
    memmove(n->props + idx, n->props + idx + 1,
            sizeof(Prop) * (size_t)(n->nprops - idx - 1));
    n->nprops--;
}

static void insert_prop(Node *n, int idx, const char *name,
                        uint32_t flags, const uint8_t *val, uint32_t len) {
    if (n->nprops == n->capprops) {
        n->capprops = n->capprops ? n->capprops * 2 : 8;
        n->props = realloc(n->props, sizeof(Prop) * (size_t)n->capprops);
    }
    if (idx > n->nprops) idx = n->nprops;
    if (idx < 0) idx = 0;
    memmove(n->props + idx + 1, n->props + idx,
            sizeof(Prop) * (size_t)(n->nprops - idx));
    n->nprops++;
    Prop *pr = &n->props[idx];
    memset(pr, 0, sizeof(*pr));
    strncpy(pr->name, name, 31);
    pr->flags = flags;
    pr->len = len;
    pr->val = malloc(len ? len : 1);
    memcpy(pr->val, val, len);
}

/* ---------------- hex helpers ---------------- */

static size_t hex_decode(const char *hex, uint8_t **out) {
    size_t hl = strlen(hex), n = hl / 2;
    uint8_t *buf = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            die("bad hex in patch file near: %.40s%s", hex + 2 * i, "");
        buf[i] = (uint8_t)v;
    }
    *out = buf;
    return n;
}

/* ---------------- serialization ---------------- */

static void ser_node(const Node *n, uint8_t **out, size_t *len, size_t *cap) {
    while (*len + 8 > *cap) { *cap *= 2; *out = realloc(*out, *cap); }
    wr32(*out + *len, (uint32_t)n->nprops); *len += 4;
    wr32(*out + *len, (uint32_t)n->nchildren); *len += 4;
    for (int i = 0; i < n->nprops; i++) {
        const Prop *pr = &n->props[i];
        while (*len + 36 + pr->len + 3 > *cap) { *cap *= 2; *out = realloc(*out, *cap); }
        memset(*out + *len, 0, 32);
        strncpy((char *)(*out + *len), pr->name, 31);
        *len += 32;
        wr32(*out + *len, pr->flags | pr->len); *len += 4;
        memcpy(*out + *len, pr->val, pr->len); *len += pr->len;
        size_t pad = (4 - (pr->len % 4)) % 4;
        memset(*out + *len, 0, pad); *len += pad;
    }
    for (int i = 0; i < n->nchildren; i++)
        ser_node(n->children[i], out, len, cap);
}

static void free_node(Node *n) {
    for (int i = 0; i < n->nprops; i++) free(n->props[i].val);
    free(n->props);
    for (int i = 0; i < n->nchildren; i++) free_node(n->children[i]);
    free(n->children);
    free(n);
}

/* ---------------- patch file ---------------- */

typedef struct Accepted { uint8_t *val; uint32_t len; int absent; } Accepted;

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <in.dtb> <patch-file> <out.dtb>\n", argv[0]);
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) die("cannot open input %s%s", argv[1], "");
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) die("read failed%s%s", "", "");
    fclose(f);

    Node *root = load_tree(buf, (size_t)sz);

    FILE *pf = fopen(argv[2], "r");
    if (!pf) die("cannot open patch file %s%s", argv[2], "");

    char line[4096];
    long ops = 0, inserts = 0, orders = 0;
    Node *pending_parent = NULL;
    int pending_index = 0;
    Node *pending_node = NULL;
    char pending_path[512] = "";

    while (fgets(line, sizeof(line), pf)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == 0) continue;
        s[strcspn(s, "\n")] = 0;

        char a1[512], a2[512], a3[8192];
        int idx;
        if (sscanf(s, "INSERTNODE %511s %d %511s", a1, &idx, a2) == 3) {
            if (pending_node) die("INSERTNODE without ENDNODE%s%s", "", "");
            Node *parent = find_node(root, a1);
            if (!parent) die("INSERTNODE parent not found: %s%s", a1, "");
            if (find_node(root, a2)) die("INSERTNODE target already exists: %s%s", a2, "");
            pending_parent = parent;
            pending_index = idx;
            pending_node = calloc(1, sizeof(Node));
            strncpy(pending_path, a2, sizeof(pending_path) - 1);
        } else if (strncmp(s, "NODEPROPN ", 10) == 0) {
            if (!pending_node) die("NODEPROPN outside INSERTNODE%s%s", "", "");
            char pname[64]; uint32_t flags; char hex[8192];
            if (sscanf(s + 10, "%63s %u %8191s", pname, &flags, hex) != 3)
                die("bad NODEPROPN line%s%s", "", "");
            uint8_t *val; size_t vl;
            if (strcmp(hex, "-") == 0) { val = NULL; vl = 0; }
            else vl = hex_decode(hex, &val);
            insert_prop(pending_node, pending_node->nprops, pname,
                        flags, val, (uint32_t)vl);
            if (strcmp(pname, "name") == 0) {
                size_t k = vl < 63 ? vl : 63;
                memcpy(pending_node->name, val, k);
                pending_node->name[k] = 0;
                char *z = memchr(pending_node->name, 0, k);
                if (z) *z = 0;
            }
            free(val);
        } else if (strncmp(s, "ENDNODE", 7) == 0) {
            if (!pending_node) die("ENDNODE without INSERTNODE%s%s", "", "");
            if (pending_index > pending_parent->nchildren)
                pending_index = pending_parent->nchildren;
            if (pending_index < 0) pending_index = 0;
            memmove(pending_parent->children + pending_index + 1,
                    pending_parent->children + pending_index,
                    sizeof(Node *) * (size_t)(pending_parent->nchildren - pending_index));
            pending_parent->children[pending_index] = pending_node;
            pending_parent->nchildren++;
            pending_node = NULL;
            inserts++;
        } else if (sscanf(s, "PROPOP %511s %63s %d %8191[^\n]", a1, a2, &idx, a3) == 4) {
            const char *rest = a3;
            Node *node = find_node(root, a1);
            if (!node) die("PROPOP node not found: %s%s", a1, "");
            Prop *found = find_prop(node, a2);

            Accepted acc[32]; int nacc = 0;
            /* pre-read following ACCEPTED lines */
            long fpos = ftell(pf);
            char la[8192];
            while (fgets(la, sizeof(la), pf)) {
                char *t = la;
                while (*t == ' ' || *t == '\t') t++;
                if (strncmp(t, "ACCEPTED ", 9) == 0) {
                    char hx[8192];
                    sscanf(t + 9, "%8191s", hx);
                    if (nacc < 32) {
                        if (strcmp(hx, "-") == 0) {
                            acc[nacc].absent = 1; acc[nacc].val = NULL; acc[nacc].len = 0;
                        } else if (strcmp(hx, "+") == 0) {
                            acc[nacc].absent = 0; acc[nacc].val = malloc(1); acc[nacc].len = 0;
                        } else {
                            acc[nacc].absent = 0;
                            acc[nacc].len = (uint32_t)hex_decode(hx, &acc[nacc].val);
                        }
                        nacc++;
                    }
                    fpos = ftell(pf);
                } else {
                    fseek(pf, fpos, SEEK_SET);
                    break;
                }
            }
            if (nacc > 0) {
                int ok = 0;
                for (int i = 0; i < nacc; i++) {
                    if (acc[i].absent && !found) { ok = 1; break; }
                    if (!acc[i].absent && found &&
                        found->len == acc[i].len &&
                        memcmp(found->val, acc[i].val, acc[i].len) == 0) { ok = 1; break; }
                }
                if (!ok) die("property preimage mismatch: %s on %s%s", a2, a1);
                for (int i = 0; i < nacc; i++) free(acc[i].val);
            }

            if (found) remove_prop(node, found);
            if (strncmp(rest, "DELETE", 6) != 0) {
                uint32_t flags; char hex[8192];
                if (sscanf(rest, "%u %8191s", &flags, hex) != 2)
                    die("bad PROPOP after clause: %s%s", rest, "");
                uint8_t *val; size_t vl;
                if (strcmp(hex, "-") == 0) { val = NULL; vl = 0; }
                else vl = hex_decode(hex, &val);
                insert_prop(node, idx, a2, flags, val, (uint32_t)vl);
                free(val);
            }
            ops++;
        } else if (strncmp(s, "ORDER ", 6) == 0) {
            char path[512];
            const char *p = s + 6;
            sscanf(p, "%511s", path);
            p += strlen(path);
            Node *node = find_node(root, path);
            if (!node) die("ORDER node not found: %s%s", path, "");
            Prop *newprops = calloc((size_t)node->nprops ? (size_t)node->nprops : 1, sizeof(Prop));
            int w = 0;
            char *save = NULL;
            for (char *nm = strtok_r((char *)p, " \t", &save); nm;
                 nm = strtok_r(NULL, " \t", &save)) {
                Prop *pr = find_prop(node, nm);
                if (pr) newprops[w++] = *pr;
            }
            for (int i = 0; i < node->nprops; i++) {
                Prop *pr = &node->props[i];
                int listed = 0;
                for (int j = 0; j < w; j++)
                    if (strcmp(newprops[j].name, pr->name) == 0) { listed = 1; break; }
                if (!listed) newprops[w++] = *pr;
            }
            if (w != node->nprops) die("ORDER lost properties on %s%s", path, "");
            free(node->props);
            node->props = newprops;
            node->capprops = node->nprops;
            orders++;
        }
    }
    fclose(pf);

    size_t olen = 0, ocap = 1 << 20;
    uint8_t *out = malloc(ocap);
    ser_node(root, &out, &olen, &ocap);

    FILE *of = fopen(argv[3], "wb");
    if (!of) die("cannot open output %s%s", argv[3], "");
    if (fwrite(out, 1, olen, of) != olen) die("write failed%s%s", "", "");
    fclose(of);

    fprintf(stderr, "dtbpatch: %ld property ops, %ld node insertions, %ld orderings; %ld -> %zu bytes\n",
            ops, inserts, orders, sz, olen);

    free_node(root);
    free(buf); free(out);
    return 0;
}
