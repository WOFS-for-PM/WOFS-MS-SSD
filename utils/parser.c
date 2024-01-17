#include "parser.h"
#include <ctype.h>

static int simple_strtoul(const char *cp, char **endp, unsigned int base) {
    unsigned long result = 0, value;

    if (!base) {
        base = 10;
        if (*cp == '0') {
            base = 8;
            cp++;
            if ((tolower(*cp) == 'x') && isxdigit(cp[1])) {
                cp++;
                base = 16;
            }
        }
    } else if (base == 16) {
        if (cp[0] == '0' && tolower(cp[1]) == 'x')
            cp += 2;
    }

    while (isxdigit(*cp) &&
           (value = isdigit(*cp) ? *cp - '0' : tolower(*cp) - 'a' + 10) <
               base) {
        result = result * base + value;
        cp++;
    }

    if (endp)
        *endp = (char *)cp;
    return result;
}

static int simple_strtol(const char *cp, char **endp, unsigned int base) {
    if (*cp == '-')
        return -simple_strtoul(cp + 1, endp, base);
    return simple_strtoul(cp, endp, base);
}

/**
 * match_one - Determines if a string matches a simple pattern
 * @s: the string to examine for presence of the pattern
 * @p: the string containing the pattern
 * @args: array of %MAX_OPT_ARGS &substring_t elements. Used to return match
 * locations.
 *
 * Description: Determines if the pattern @p is present in string @s. Can only
 * match extremely simple token=arg style patterns. If the pattern is found,
 * the location(s) of the arguments will be returned in the @args array.
 */
static int match_one(char *s, const char *p, substring_t args[]) {
    char *meta;
    int argc = 0;

    if (!p)
        return 1;

    while (1) {
        int len = -1;
        meta = strchr(p, '%');
        if (!meta)
            return strcmp(p, s) == 0;

        if (strncmp(p, s, meta - p))
            return 0;

        s += meta - p;
        p = meta + 1;

        if (isdigit(*p))
            len = simple_strtoul(p, (char **)&p, 10);
        else if (*p == '%') {
            if (*s++ != '%')
                return 0;
            p++;
            continue;
        }

        if (argc >= MAX_OPT_ARGS)
            return 0;

        args[argc].from = s;
        switch (*p++) {
            case 's': {
                size_t str_len = strlen(s);

                if (str_len == 0)
                    return 0;
                if (len == -1 || len > str_len)
                    len = str_len;
                args[argc].to = s + len;
                break;
            }
            case 'd':
                simple_strtol(s, &args[argc].to, 0);
                goto num;
            case 'u':
                simple_strtoul(s, &args[argc].to, 0);
                goto num;
            case 'o':
                simple_strtoul(s, &args[argc].to, 8);
                goto num;
            case 'x':
                simple_strtoul(s, &args[argc].to, 16);
            num:
                if (args[argc].to == args[argc].from)
                    return 0;
                break;
            default:
                return 0;
        }
        s = args[argc].to;
        argc++;
    }
}

/**
 * match_token - Find a token (and optional args) in a string
 * @s: the string to examine for token/argument pairs
 * @table: match_table_t describing the set of allowed option tokens and the
 * arguments that may be associated with them. Must be terminated with a
 * &struct match_token whose pattern is set to the NULL pointer.
 * @args: array of %MAX_OPT_ARGS &substring_t elements. Used to return match
 * locations.
 *
 * Description: Detects which if any of a set of token strings has been passed
 * to it. Tokens can include up to %MAX_OPT_ARGS instances of basic c-style
 * format identifiers which will be taken into account when matching the
 * tokens, and whose locations will be returned in the @args array.
 */
int match_token(char *s, const match_table_t table, substring_t args[]) {
    const struct match_token *p;

    for (p = table; !match_one(s, p->pattern, args); p++)
        ;

    return p->token;
}

/**
 * match_strdup - allocate a new string with the contents of a substring_t
 * @s: &substring_t to copy
 *
 * Description: Allocates and returns a string filled with the contents of
 * the &substring_t @s. The caller is responsible for freeing the returned
 * string with kfree().
 *
 * Return: the address of the newly allocated NUL-terminated string or
 * %NULL on error.
 */
char *match_strdup(const substring_t *s) {
    return kmemdup_nul(s->from, s->to - s->from, GFP_KERNEL);
}

/**
 * match_number - scan a number in the given base from a substring_t
 * @s: substring to be scanned
 * @result: resulting integer on success
 * @base: base to use when converting string
 *
 * Description: Given a &substring_t and a base, attempts to parse the substring
 * as a number in that base.
 *
 * Return: On success, sets @result to the integer represented by the
 * string and returns 0. Returns -ENOMEM, -EINVAL, or -ERANGE on failure.
 */
static int match_number(substring_t *s, int *result, int base) {
    char *endp;
    char *buf;
    int ret;
    long val;

    buf = match_strdup(s);
    if (!buf)
        return -ENOMEM;

    ret = 0;
    val = simple_strtol(buf, &endp, base);
    if (endp == buf)
        ret = -EINVAL;
    else if (val < (long)INT_MIN || val > (long)INT_MAX)
        ret = -ERANGE;
    else
        *result = (int)val;
    kfree(buf);
    return ret;
}

int match_int(substring_t *s, int *result) {
    return match_number(s, result, 0);
}