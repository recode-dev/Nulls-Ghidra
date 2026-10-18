import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class Dump extends GhidraScript {

    private static final Pattern THUNK = Pattern.compile("thunk_FUN_([0-9a-fA-F]+)");
    private static final Pattern PLAIN = Pattern.compile("FUN_([0-9a-fA-F]+)");
    private static final Pattern HEX = Pattern.compile("fcn\\.([0-9a-fA-F]+)");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String codePath = args.length > 0 && !args[0].isEmpty() ? args[0] : "decompiled.c";
        String jsonPath = args.length > 1 && !args[1].isEmpty() ? args[1] : ".aflj";
        boolean bodies = args.length < 3 || !"names".equals(args[2]);

        List<Function> funcs = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            funcs.add(iterator.next());
        }
        writeFunctions(jsonPath, funcs);
        println("functions " + funcs.size());

        if (!bodies) {
            return;
        }

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
