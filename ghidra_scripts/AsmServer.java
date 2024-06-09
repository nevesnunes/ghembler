//Assembly server
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Executors;

import generic.theme.GThemeDefaults.Colors;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseErrorResult;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyCompletion;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

public class AsmServer extends GhidraScript {

	private HttpServer server;
	private Assembler assembler;
	private Disassembler disassembler;
	private FlatProgramAPI fpa;

	private static final String ASSEMBLER_COMPLETION_TYPE = "type";
	private static final String ASSEMBLER_COMPLETION_DATA = "data";

	private static final String DISASSEMBLER_ADDRESS = "address";
	private static final String DISASSEMBLER_DATA = "data";

	@Override
	protected void run() throws Exception {
		setupProgram();
		setupServer();

		// Keep script running while we handle requests
		while (true) {
			try {
				Thread.sleep(500);
				monitor.checkCancelled();
			} catch (CancelledException e) {
				println("Stopping server...");
				break;
			}
		}
	}

	private void setupProgram() throws MemoryBlockException, LockException, NotFoundException {
		assembler = Assemblers.getAssembler(currentProgram);
		disassembler = Disassembler.getDisassembler(currentProgram, monitor, DisassemblerMessageListener.CONSOLE);
		fpa = new FlatProgramAPI(currentProgram, monitor);
	}

	private void setupServer() throws IOException {
		server = HttpServer.create(new InetSocketAddress(18000), 0);

		AssemblerHandler assemblerHandler = new AssemblerHandler();
		server.createContext("/assemble", assemblerHandler);
		DisassemblerHandler disassemblerHandler = new DisassemblerHandler();
		server.createContext("/disassemble", disassemblerHandler);

		server.setExecutor(Executors.newCachedThreadPool());
		server.start();
		println("Listening at port 18000...");
	}

	@Override
	public void cleanup(boolean success) {
		if (server != null) {
			server.stop(1);
			println("Stopped server.");
		}
	}

	class AssemblerHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange he) throws IOException {
			if (he.getRequestMethod().equals("OPTIONS")) {
				addCORS(he, true);
				he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
				he.close();
				return;
			}

			Headers requestHeaders = he.getRequestHeaders();
			InputStream is = he.getRequestBody();
			byte[] data = is.readAllBytes();
			String line = new String(data);
			Address at = currentAddress; // FIXME

			he.getResponseHeaders().put("Access-Control-Allow-Origin", Collections.singletonList("*"));
			he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			try (OutputStream os = he.getResponseBody()) {
				JsonWriter jsonWriter = new JsonWriter(new OutputStreamWriter(os));
				jsonWriter.beginArray();

				for (final AssemblyCompletion co : computeCompletions(at, line)) {
					JsonObject json = new JsonObject();
					if (co instanceof AssemblyInstruction) {
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "bytes");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, co.getDisplay());
					} else if (co instanceof AssemblySuggestion) {
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "suggestion");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, co.getText());
					} else {
						json.addProperty(ASSEMBLER_COMPLETION_TYPE, "error");
						json.addProperty(ASSEMBLER_COMPLETION_DATA, co.getDisplay());
					}
					gson.toJson(json, jsonWriter);
				}

				jsonWriter.endArray();
				jsonWriter.close();
			} finally {
				he.close();
			}
		}
	}

	class DisassemblerHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange he) throws IOException {
			if (he.getRequestMethod().equals("OPTIONS")) {
				addCORS(he, true);
				he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
				he.close();
				return;
			}

			Headers requestHeaders = he.getRequestHeaders();
			int contentLength = Integer.parseInt(requestHeaders.getFirst("Content-length"));
			InputStream is = he.getRequestBody();
			List<String> instructions = new ArrayList<>();
			try (JsonReader jsonReader = new JsonReader(new InputStreamReader(is))) {
				jsonReader.beginArray();

				while (jsonReader.hasNext()) {
					jsonReader.beginObject();

					long addressOffset = 0;
					String display = "";
					while (jsonReader.hasNext()) {
						String name = jsonReader.nextName();
						if (name.equals(DISASSEMBLER_ADDRESS)) {
							addressOffset = jsonReader.nextLong();
						} else if (name.equals(DISASSEMBLER_DATA)) {
							display = jsonReader.nextString();
						} else {
							throw new RuntimeException(String.format("Unknown request name='%s'", name));
						}
					}

					Address address = toAddr(addressOffset);
					putAt(address, display);
					disassembler.disassemble(address, new AddressSet(address), false);
					Instruction ins = currentProgram.getListing().getInstructionAt(address);
					if (ins == null) {
						throw new RuntimeException(
								String.format("Null instruction @ 0x%08x", address.getUnsignedOffset()));
					}
					instructions.add(ins.toString());

					jsonReader.endObject();
				}

				jsonReader.endArray();
			} catch (Exception e) {
				printerr(e.getMessage());
				throw e;
			}

			he.getResponseHeaders().put("Access-Control-Allow-Origin", Collections.singletonList("*"));
			he.sendResponseHeaders(HttpURLConnection.HTTP_OK, 0);
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			try (OutputStream os = he.getResponseBody()) {
				JsonWriter jsonWriter = new JsonWriter(new OutputStreamWriter(os));
				JsonArray jsonArray = new JsonArray();
				for (final String ins : instructions) {
					jsonArray.add(new JsonPrimitive(ins));
				}
				gson.toJson(jsonArray, jsonWriter);
				jsonWriter.close();
			} finally {
				he.close();
			}
		}
	}

	private void addCORS(HttpExchange exchange, boolean isOptions) {
		exchange.getResponseHeaders().put("Access-Control-Allow-Headers", List.of("Origin", "Content-Type"));
		exchange.getResponseHeaders().put("Access-Control-Allow-Methods", List.of("GET", "POST", "OPTIONS"));
		exchange.getResponseHeaders().put("Access-Control-Allow-Origin", List.of("*"));
		if (isOptions) {
			exchange.getResponseHeaders().put("Allow", List.of("GET", "POST", "OPTIONS"));
		}
	}

	private void putAt(Address address, String hexBytes) {
		if (hexBytes.isBlank()) {
			throw new RuntimeException(String.format("Null bytes to put @ 0x%08x", address.getUnsignedOffset()));
		}
		byte[] memBytes = HexFormat.of().parseHex(hexBytes.replaceAll("\\s+", ""));

		boolean isContained = false;
		for (MemoryBlock mb : currentProgram.getMemory().getBlocks()) {
			if (mb.contains(address)) {
				isContained = true;
				break;
			}
		}

		try {
			if (!isContained) {
				// Create a new 0x10000 sized memory block containing the given address
				long startOffset = address.getUnsignedOffset() & 0xffff0000L;
				MemoryBlock mb = fpa.createMemoryBlock(Long.toHexString(startOffset), fpa.toAddr(startOffset), null, 0x10000, false);
				currentProgram.getMemory().convertToInitialized(mb, (byte) '\0');
			} else {
				// Clear any previously disassembled instructions
				currentProgram
						.getListing()
						.clearCodeUnits(address, toAddr(address.getUnsignedOffset() + memBytes.length), false);
			}
			currentProgram.getMemory().setBytes(address, memBytes, 0, memBytes.length);
		} catch (Exception e) {
			printerr(e.getMessage());
			throw new RuntimeException(e);
		}
	}

	private Collection<AssemblyCompletion> computeCompletions(Address at, String line) {
		final AssemblyPatternBlock ctx = Objects.requireNonNull(getContext(assembler, at));

		Set<AssemblyCompletion> result = new TreeSet<>();
		Collection<AssemblyParseResult> parses = assembler.parseLine(line);
		for (AssemblyParseResult parse : parses) {
			if (parse.isError()) {
				AssemblyParseErrorResult err = (AssemblyParseErrorResult) parse;
				String buffer = err.getBuffer();
				for (String s : err.getSuggestions()) {
					if (s.startsWith(buffer)) {
						result.add(new AssemblySuggestion(s.substring(buffer.length()), formatSuggestion(line, s, buffer)));
					}
				}
			} else {
				AssemblyResolutionResults sems = assembler.resolveTree(parse, at, ctx);
				for (AssemblyResolution ar : sems) {
					if (ar.isError()) {
						result.add(new AssemblyError("", ar.toString()));
						continue;
					}
					AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
					for (byte[] ins : rc.possibleInsVals(ctx)) {
						result.add(new AssemblyInstruction(line, Arrays.copyOf(ins, ins.length), 0));
					}
				}
			}
		}

		if (result.isEmpty()) {
			result.add(new AssemblyError("", String.format("Invalid instruction and/or prefix: '%s'", line)));
		}
		return result;
	}

	protected String formatSuggestion(String prefix, String suggestion, String bufferleft) {
		String extra = suggestion.substring(bufferleft.length());
		String before = prefix.substring(0, prefix.length() - bufferleft.length());
		return String.format("%s%s%s", before, bufferleft, extra);
	}

	protected AssemblyPatternBlock getContext(Assembler assembler, Address address) {
		return assembler.getContextAt(address).fillMask();
	}

	/**
	 * Represents the description of an error encountered during parsing or
	 * assembling
	 */
	static class AssemblyError extends AssemblyCompletion {
		private String text;

		public AssemblyError(String text, String desc) {
			super(text, desc, Colors.ERROR, 1);
			this.text = text;
		}

		@Override
		public String getText() {
			return text;
		}
	}

	/**
	 * Represents a textual suggestion to complete or partially complete an assembly instruction
	 */
	static class AssemblySuggestion extends AssemblyCompletion {
		public AssemblySuggestion(String text, String display) {
			super(text, display, null, 1);
		}

		@Override
		public boolean getCanDefault() {
			return true;
		}
	}

	/**
	 * Represents an encoding for a complete assembly instruction
	 */
	static class AssemblyInstruction extends AssemblyCompletion {
		private byte[] data;

		public AssemblyInstruction(String text, byte[] data, int preference) {
			super("", NumericUtilities.convertBytesToString(data, " "), Colors.FOREGROUND, -preference);
			this.data = data;
		}

		public byte[] getData() {
			return data;
		}

		@Override
		public int compareTo(AssemblyCompletion ac) {
			if (!(ac instanceof AssemblyInstruction)) {
				return super.compareTo(ac);
			}
			AssemblyInstruction that = (AssemblyInstruction) ac;
			if (this.data.length != that.data.length) {
				return this.data.length - that.data.length;
			}
			return super.compareTo(ac);
		}
	}
}
