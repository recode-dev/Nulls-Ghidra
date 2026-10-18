import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;

public class Dump extends GhidraScript {

    private static final Pattern THUNK = Pattern.compile("thunk_FUN_([0-9a-fA-F]+)");
    private static final Pattern PLAIN = Pattern.compile("FUN_([0-9a-fA-F]+)");
    private static final Pattern HEX = Pattern.compile("fcn\\.([0-9a-fA-F]+)");
    private static final Pattern BAD = Pattern.compile("[^A-Za-z0-9_.:]");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "all";
        String codePath = args.length > 1 && !args[1].isEmpty() ? args[1] : "decompiled.c";
        String jsonPath = args.length > 2 && !args[2].isEmpty() ? args[2] : "funcs.json";
        String namesPath = args.length > 3 ? args[3] : "";

        if ("pre".equals(mode)) {
            tune();
            return;
        }

        if (!namesPath.isEmpty() && new File(namesPath).isFile()) {
            int renamed = applyNames(namesPath);
            println("renamed " + renamed);
        }

        List<Function> funcs = collect();
        println("functions " + funcs.size());

        if ("names".equals(mode)) {
            writeFunctions(jsonPath, funcs);
            return;
        }

        int from = 0;
        int to = funcs.size();
        if ("shard".equals(mode) && args.length > 5) {
            from = Math.max(0, Integer.parseInt(args[4]));
            to = Math.min(funcs.size(), Integer.parseInt(args[5]));
        }
        if (from >= to) {
            println("empty shard " + from + " " + to);
            return;
        }

        decompile(funcs.subList(from, to), codePath);
    }

    private List<Function> collect() {
        List<Function> funcs = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            funcs.add(iterator.next());
        }
        return funcs;
    }

    private void decompile(List<Function> funcs, String codePath) throws Exception {
        DecompInterface dec = new DecompInterface();
        dec.toggleCCode(true);
        dec.toggleSyntaxTree(false);
        dec.setSimplificationStyle("decompile");
        if (!dec.openProgram(currentProgram)) {
            printerr("decompiler failed to open program");
            return;
        }

        int done = 0;
        int failed = 0;
        try (BufferedWriter out = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(codePath), StandardCharsets.UTF_8))) {
            for (Function func : funcs) {
                if (monitor.isCancelled()) {
                    break;
                }
                try {
                    DecompileResults res = dec.decompileFunction(func, 60, monitor);
                    if (res == null || !res.decompileCompleted()) {
                        failed++;
                        continue;
                    }
                    String text = res.getDecompiledFunction().getC();
                    if (text == null || text.isEmpty()) {
                        failed++;
                        continue;
                    }
                    out.write(marker(func));
                    out.write(normalize(text));
                    out.write('\n');
                    done++;
                } catch (Exception error) {
                    failed++;
                }
            }
        } finally {
            dec.dispose();
        }
        println("bodies " + done + " failed " + failed);
    }

    private void tune() {
        String[][] options = {
            {"Decompiler Parameter ID", "true"},
            {"Decompiler Switch Analysis", "true"},
            {"Create Address Tables", "true"},
        };
        for (String[] pair : options) {
            try {
                setAnalysisOption(currentProgram, pair[0], pair[1]);
            } catch (Exception error) {
                println("option skipped " + pair[0]);
            }
        }
    }

    private int applyNames(String path) throws Exception {
        int renamed = 0;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int tab = line.indexOf('\t');
                if (tab <= 0) {
                    continue;
                }
                String name = sanitize(line.substring(0, tab).trim());
                if (name.isEmpty()) {
                    continue;
                }
                long value;
                try {
                    value = address(line.substring(tab + 1).trim());
                } catch (NumberFormatException error) {
                    continue;
                }
                Address target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                Function func = getFunctionAt(target);
                if (func == null) {
                    continue;
                }
                try {
                    func.setName(name, SourceType.USER_DEFINED);
                    renamed++;
                } catch (Exception error) {
                    continue;
                }
            }
        }
        return renamed;
    }

    private long address(String token) {
        if (token.startsWith("0x") || token.startsWith("0X")) {
            return Long.parseLong(token.substring(2), 16);
        }
        return Long.parseLong(token);
    }

    private String sanitize(String name) {
        String clean = BAD.matcher(name).replaceAll("_");
        if (clean.isEmpty()) {
            return clean;
        }
        if (Character.isDigit(clean.charAt(0))) {
            clean = "_" + clean;
        }
        return clean;
    }

    private String marker(Function func) {
        return "// " + func.getName() + " 0x" + Long.toHexString(func.getEntryPoint().getOffset())
                + " size 0x" + Long.toHexString(func.getBody().getNumAddresses()) + "\n";
    }

    private void writeFunctions(String path, List<Function> funcs) throws Exception {
        try (BufferedWriter out = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(path), StandardCharsets.UTF_8))) {
            out.write('[');
            for (int index = 0; index < funcs.size(); index++) {
                Function func = funcs.get(index);
                if (index > 0) {
                    out.write(',');
                }
                out.write("{\"name\":\"");
                out.write(escape(func.getName()));
                out.write("\",\"offset\":");
                out.write(Long.toString(func.getEntryPoint().getOffset()));
                out.write('}');
            }
            out.write(']');
        }
    }

    private String normalize(String text) {
        text = THUNK.matcher(text).replaceAll("fcn.$1");
        text = PLAIN.matcher(text).replaceAll("fcn.$1");
        Matcher match = HEX.matcher(text);
        StringBuffer buffer = new StringBuffer(text.length());
        while (match.find()) {
            match.appendReplacement(buffer, "fcn." + match.group(1).toLowerCase());
        }
        match.appendTail(buffer);
        return buffer.toString();
    }

    private String escape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (ch == '"' || ch == '\\') {
                out.append('\\');
            }
            out.append(ch);
        }
        return out.toString();
    }
}
