-- SMOO USB postdissector for Wireshark.
--
-- Adds SMOO-aware annotations to USB transfers:
-- - decodes interrupt Request/Response payloads
-- - tracks CONFIG_EXPORTS to learn block sizes
-- - tags bulk transfers with inferred Request metadata
--
-- Limitations:
-- - bulk payloads are untagged on the wire; inference is by order/length.
-- - if read sizes are uniform, reordering may not be detectable.

local smoo = Proto("smoo", "SMOO")

local pf = smoo.fields
pf.req_op = ProtoField.uint8("smoo.request.op", "SMOO Request Op", base.DEC)
pf.req_export_id = ProtoField.uint32("smoo.request.export_id", "SMOO Export ID", base.DEC)
pf.req_request_id = ProtoField.uint32("smoo.request.request_id", "SMOO Request ID", base.DEC)
pf.req_lba = ProtoField.uint64("smoo.request.lba", "SMOO LBA", base.DEC)
pf.req_blocks = ProtoField.uint32("smoo.request.num_blocks", "SMOO Blocks", base.DEC)
pf.req_flags = ProtoField.uint32("smoo.request.flags", "SMOO Request Flags", base.HEX)

pf.resp_op = ProtoField.uint8("smoo.response.op", "SMOO Response Op", base.DEC)
pf.resp_status = ProtoField.uint8("smoo.response.status", "SMOO Status", base.DEC)
pf.resp_export_id = ProtoField.uint32("smoo.response.export_id", "SMOO Export ID", base.DEC)
pf.resp_request_id = ProtoField.uint32("smoo.response.request_id", "SMOO Request ID", base.DEC)
pf.resp_lba = ProtoField.uint64("smoo.response.lba", "SMOO LBA", base.DEC)
pf.resp_blocks = ProtoField.uint32("smoo.response.num_blocks", "SMOO Blocks", base.DEC)
pf.resp_flags = ProtoField.uint32("smoo.response.flags", "SMOO Response Flags", base.HEX)

pf.bulk_dir = ProtoField.string("smoo.bulk.dir", "SMOO Bulk Direction")
pf.bulk_export_id = ProtoField.uint32("smoo.bulk.export_id", "SMOO Export ID", base.DEC)
pf.bulk_request_id = ProtoField.uint32("smoo.bulk.request_id", "SMOO Request ID", base.DEC)
pf.bulk_lba = ProtoField.uint64("smoo.bulk.lba", "SMOO LBA", base.DEC)
pf.bulk_blocks = ProtoField.uint32("smoo.bulk.num_blocks", "SMOO Blocks", base.DEC)
pf.bulk_expected_len = ProtoField.uint32("smoo.bulk.expected_len", "SMOO Expected Len", base.DEC)
pf.bulk_actual_len = ProtoField.uint32("smoo.bulk.actual_len", "SMOO Actual Len", base.DEC)
pf.bulk_mismatch = ProtoField.bool("smoo.bulk.len_mismatch", "SMOO Length Mismatch")
pf.bulk_orphan = ProtoField.bool("smoo.bulk.orphan", "SMOO Orphan Bulk")

pf.cfg_export_id = ProtoField.uint32("smoo.config.export_id", "SMOO Export ID", base.DEC)
pf.cfg_block_size = ProtoField.uint32("smoo.config.block_size", "SMOO Block Size", base.DEC)
pf.cfg_size_bytes = ProtoField.uint64("smoo.config.size_bytes", "SMOO Size Bytes", base.DEC)

pf.note = ProtoField.string("smoo.note", "SMOO Note")

local CONFIG = {
    interrupt_in = 0x81,
    interrupt_out = 0x01,
    bulk_in = 0x82,
    bulk_out = 0x02,
    default_block_size = 4096,
    config_exports_req_type = 0x41,
    config_exports_request = 0x02,
}

local f_endpoint = Field.new("usb.endpoint_address")
local f_transfer = Field.new("usb.transfer_type")
local f_capdata = Field.new("usb.capdata")
local f_bus = Field.new("usb.bus_id")
local f_dev = Field.new("usb.device_address")
local f_ctrl_req = Field.new("usb.control.bRequest")
local f_ctrl_type = Field.new("usb.control.bmRequestType")
local f_len = Field.new("usb.data_len")

local function to_number(fieldinfo)
    if not fieldinfo then
        return nil
    end
    local s = tostring(fieldinfo)
    if not s then
        return nil
    end
    return tonumber(s)
end

local function hex_to_bytes(s)
    local bytes = {}
    if not s then
        return bytes
    end
    for byte in s:gmatch("[0-9A-Fa-f][0-9A-Fa-f]") do
        bytes[#bytes + 1] = tonumber(byte, 16)
    end
    return bytes
end

local function le_u32(b, i)
    return b[i] + b[i + 1] * 256 + b[i + 2] * 65536 + b[i + 3] * 16777216
end

local function le_u64(b, i)
    local lo = le_u32(b, i)
    local hi = le_u32(b, i + 4)
    return lo + hi * 4294967296
end

local function op_name(op)
    if op == 0 then return "Read" end
    if op == 1 then return "Write" end
    if op == 2 then return "Flush" end
    if op == 3 then return "Discard" end
    return "Unknown"
end

local function queue_new()
    return { items = {}, head = 1, tail = 0 }
end

local function queue_push(q, item)
    q.tail = q.tail + 1
    q.items[q.tail] = item
end

local function queue_pop(q)
    if q.head > q.tail then
        return nil
    end
    local item = q.items[q.head]
    q.items[q.head] = nil
    q.head = q.head + 1
    return item
end

local function device_key()
    local bus = tostring(f_bus() or "?")
    local dev = tostring(f_dev() or "?")
    return bus .. ":" .. dev
end

local state = {}

local function state_for_device()
    local key = device_key()
    local st = state[key]
    if not st then
        st = {
            exports = {},
            read_q = queue_new(),
            write_q = queue_new(),
            pending = {},
        }
        state[key] = st
    end
    return st
end

local function parse_request(bytes)
    if #bytes ~= 28 then
        return nil
    end
    local op = bytes[1]
    local request_id = le_u32(bytes, 5)
    local export_id = le_u32(bytes, 9)
    local lba = le_u64(bytes, 13)
    local num_blocks = le_u32(bytes, 21)
    local flags = le_u32(bytes, 25)
    return {
        op = op,
        request_id = request_id,
        export_id = export_id,
        lba = lba,
        num_blocks = num_blocks,
        flags = flags,
    }
end

local function parse_response(bytes)
    if #bytes ~= 28 then
        return nil
    end
    local op = bytes[1]
    local status = bytes[2]
    local request_id = le_u32(bytes, 5)
    local export_id = le_u32(bytes, 9)
    local lba = le_u64(bytes, 13)
    local num_blocks = le_u32(bytes, 21)
    local flags = le_u32(bytes, 25)
    return {
        op = op,
        status = status,
        request_id = request_id,
        export_id = export_id,
        lba = lba,
        num_blocks = num_blocks,
        flags = flags,
    }
end

local function parse_config_exports(bytes)
    if #bytes < 8 then
        return nil
    end
    local version = bytes[1] + bytes[2] * 256
    local count = bytes[3] + bytes[4] * 256
    local flags = le_u32(bytes, 5)
    if version ~= 0 or flags ~= 0 then
        return nil
    end
    local expected = 8 + count * 24
    if #bytes ~= expected then
        return nil
    end
    local entries = {}
    local offset = 9
    for i = 1, count do
        local export_id = le_u32(bytes, offset)
        local block_size = le_u32(bytes, offset + 4)
        local size_bytes = le_u64(bytes, offset + 8)
        entries[#entries + 1] = {
            export_id = export_id,
            block_size = block_size,
            size_bytes = size_bytes,
        }
        offset = offset + 24
    end
    return entries
end

local function add_request_tree(tree, req)
    local subtree = tree:add(smoo, "SMOO Request")
    subtree:add(pf.req_op, req.op)
    subtree:add(pf.req_export_id, req.export_id)
    subtree:add(pf.req_request_id, req.request_id)
    subtree:add(pf.req_lba, req.lba)
    subtree:add(pf.req_blocks, req.num_blocks)
    subtree:add(pf.req_flags, req.flags)
    subtree:add(pf.note, op_name(req.op))
end

local function add_response_tree(tree, resp)
    local subtree = tree:add(smoo, "SMOO Response")
    subtree:add(pf.resp_op, resp.op)
    subtree:add(pf.resp_status, resp.status)
    subtree:add(pf.resp_export_id, resp.export_id)
    subtree:add(pf.resp_request_id, resp.request_id)
    subtree:add(pf.resp_lba, resp.lba)
    subtree:add(pf.resp_blocks, resp.num_blocks)
    subtree:add(pf.resp_flags, resp.flags)
    subtree:add(pf.note, op_name(resp.op))
end

local function add_bulk_tree(tree, bulk_dir, entry, actual_len, mismatch, orphan)
    local subtree = tree:add(smoo, "SMOO Bulk")
    subtree:add(pf.bulk_dir, bulk_dir)
    if entry then
        subtree:add(pf.bulk_export_id, entry.export_id)
        subtree:add(pf.bulk_request_id, entry.request_id)
        subtree:add(pf.bulk_lba, entry.lba)
        subtree:add(pf.bulk_blocks, entry.num_blocks)
        subtree:add(pf.bulk_expected_len, entry.expected_len)
    end
    subtree:add(pf.bulk_actual_len, actual_len)
    if mismatch then
        subtree:add(pf.bulk_mismatch, true)
        subtree:add(pf.note, "bulk length mismatch")
    end
    if orphan then
        subtree:add(pf.bulk_orphan, true)
        subtree:add(pf.note, "bulk transfer with no queued request")
    end
end

local function add_config_tree(tree, entries)
    local subtree = tree:add(smoo, "SMOO CONFIG_EXPORTS")
    for _, entry in ipairs(entries) do
        local et = subtree:add(smoo, "Export " .. entry.export_id)
        et:add(pf.cfg_export_id, entry.export_id)
        et:add(pf.cfg_block_size, entry.block_size)
        et:add(pf.cfg_size_bytes, entry.size_bytes)
    end
end

function smoo.dissector(buffer, pinfo, tree)
    local transfer_type = to_number(f_transfer())
    local endpoint = to_number(f_endpoint())
    local capdata = f_capdata()
    local capbytes = hex_to_bytes(capdata and tostring(capdata) or nil)
    local st = state_for_device()

    if transfer_type == 1 and endpoint == CONFIG.interrupt_in then
        local req = parse_request(capbytes)
        if req then
            local export = st.exports[req.export_id]
            local block_size = export and export.block_size or CONFIG.default_block_size
            req.expected_len = req.num_blocks * block_size
            local key = tostring(req.export_id) .. ":" .. tostring(req.request_id)
            st.pending[key] = req
            if req.op == 0 then
                queue_push(st.read_q, req)
            elseif req.op == 1 then
                queue_push(st.write_q, req)
            end
            add_request_tree(tree, req)
        end
        return
    end

    if transfer_type == 1 and endpoint == CONFIG.interrupt_out then
        local resp = parse_response(capbytes)
        if resp then
            local key = tostring(resp.export_id) .. ":" .. tostring(resp.request_id)
            st.pending[key] = nil
            add_response_tree(tree, resp)
        end
        return
    end

    if transfer_type == 3 and (endpoint == CONFIG.bulk_out or endpoint == CONFIG.bulk_in) then
        local bulk_dir = endpoint == CONFIG.bulk_out and "read" or "write"
        local queue = endpoint == CONFIG.bulk_out and st.read_q or st.write_q
        local entry = queue_pop(queue)
        local actual_len = to_number(f_len()) or #capbytes
        if entry then
            local mismatch = entry.expected_len ~= 0 and actual_len ~= entry.expected_len
            add_bulk_tree(tree, bulk_dir, entry, actual_len, mismatch, false)
        else
            add_bulk_tree(tree, bulk_dir, nil, actual_len, false, true)
        end
        return
    end

    local ctrl_req = to_number(f_ctrl_req())
    local ctrl_type = to_number(f_ctrl_type())
    if ctrl_req == CONFIG.config_exports_request and ctrl_type == CONFIG.config_exports_req_type then
        local entries = parse_config_exports(capbytes)
        if entries then
            for _, entry in ipairs(entries) do
                st.exports[entry.export_id] = {
                    block_size = entry.block_size,
                    size_bytes = entry.size_bytes,
                }
            end
            add_config_tree(tree, entries)
        end
    end
end

register_postdissector(smoo)
