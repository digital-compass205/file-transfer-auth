package com.filetransfer.common.json;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Minimal JSON support for flat (non-nested) objects with string/number
 * values only. The protocol in this project never needs more than that
 * (manifests, tokens, CSR/cert PEM blobs as strings) — a full JSON library
 * is unnecessary third-party surface for that shape.
 */
public final class SimpleJson {

    private SimpleJson() {
    }

    public static String writeFlatObject(Map<String, ?> fields) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, ?> entry : fields.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escape(entry.getKey())).append("\":");
            Object value = entry.getValue();
            if (value instanceof Number) {
                sb.append(value.toString());
            } else if (value == null) {
                sb.append("null");
            } else {
                sb.append('"').append(escape(value.toString())).append('"');
            }
        }
        sb.append('}');
        return sb.toString();
    }

    public static Map<String, String> parseFlatObject(String json) {
        Map<String, String> result = new LinkedHashMap<>();
        Parser p = new Parser(json);
        p.skipWhitespace();
        p.expect('{');
        p.skipWhitespace();
        if (p.peek() == '}') {
            p.next();
            return result;
        }
        while (true) {
            p.skipWhitespace();
            String key = p.parseString();
            p.skipWhitespace();
            p.expect(':');
            p.skipWhitespace();
            String value = p.parseValue();
            result.put(key, value);
            p.skipWhitespace();
            char c = p.next();
            if (c == '}') {
                break;
            }
            if (c != ',') {
                throw new IllegalArgumentException("Malformed JSON near index " + p.pos);
            }
        }
        return result;
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static final class Parser {
        private static final Pattern NUMBER =
                Pattern.compile("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][-+]?[0-9]+)?");

        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        char peek() {
            if (pos >= s.length()) {
                throw new IllegalArgumentException("Unexpected end of JSON input");
            }
            return s.charAt(pos);
        }

        char next() {
            char c = peek();
            pos++;
            return c;
        }

        void expect(char c) {
            char actual = next();
            if (actual != c) {
                throw new IllegalArgumentException("Expected '" + c + "' but got '" + actual + "' at index " + (pos - 1));
            }
        }

        void skipWhitespace() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }

        String parseValue() {
            char c = peek();
            if (c == '"') {
                return parseString();
            }
            int start = pos;
            while (pos < s.length() && "-+.0123456789eEtruefalsn".indexOf(s.charAt(pos)) >= 0) {
                pos++;
            }
            if (pos == start) {
                throw new IllegalArgumentException("Malformed JSON value at index " + pos);
            }
            String literal = s.substring(start, pos);
            // The scan above is a permissive character sweep, so it also accepts
            // things like "tru" or "1.2.3". Validate the result rather than
            // handing a caller a value that never appeared in the input.
            if (!literal.equals("true") && !literal.equals("false") && !literal.equals("null")
                    && !NUMBER.matcher(literal).matches()) {
                throw new IllegalArgumentException(
                        "Malformed JSON value '" + literal + "' at index " + start);
            }
            return literal;
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char esc = next();
                    switch (esc) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            // Bounds-check before substring: a truncated escape at
                            // the end of input would otherwise raise
                            // StringIndexOutOfBoundsException, which is not an
                            // IllegalArgumentException and so would surface to
                            // callers as a 500 rather than a 400.
                            if (pos + 4 > s.length()) {
                                throw new IllegalArgumentException(
                                        "Truncated \\u escape at index " + pos);
                            }
                            String hex = s.substring(pos, pos + 4);
                            pos += 4;
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException e) {
                                throw new IllegalArgumentException(
                                        "Invalid \\u escape '" + hex + "' at index " + (pos - 4));
                            }
                            break;
                        default:
                            throw new IllegalArgumentException("Unknown escape \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }
    }
}
