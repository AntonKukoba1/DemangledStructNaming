#include <ida.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <segment.hpp>
#include <struct.hpp>
#include <regex>
#include <string>
#include <set>


std::set<qstring> GetMemberNames(struc_t* structToChange, size_t structSize)
{
    std::set<qstring> result;
    for (int memberOffset = 0; memberOffset < structSize; )
    {
        member_t* member = get_member(structToChange, memberOffset);
        qstring name = get_member_name(member->id);
        result.insert(name);
        memberOffset = member->eoff;
    }

    return result;
}

void ChangeMembers(ea_t baseAddr, struc_t* structToChange)
{
    size_t structSize = get_struc_size(structToChange);
    std::set<qstring> methods = GetMemberNames(structToChange, structSize);

    for (int memberOffset = 0; memberOffset < structSize; )
    {
        member_t* member = get_member(structToChange, memberOffset);
        if (!member) {
            msg("Error getting member at offset %d\n", memberOffset);
            break;
        }

        qstring oldMemberName = get_member_name(member->id);

        ea_t funcAddr = get_qword(baseAddr + memberOffset);
        qstring funcName;
        get_ea_name(&funcName, funcAddr, GN_SHORT | GN_DEMANGLED);

        qstring newName;

        std::regex methodNameRegex("::([a-zA-Z_][a-zA-Z0-9_]+)\\(");
        std::smatch match;
        std::string oldName = funcName.c_str();
        if (std::regex_search(oldName, match, methodNameRegex))
        {
            std::string pureMethodName = match[1].str();
            newName = pureMethodName.c_str();
        }
        else if (oldName.find("destructor") != std::string::npos)
            newName = "Destroy";

        if (!newName.empty())
        {
            if (methods.find(newName) == methods.end())
            {
                set_member_name(structToChange, memberOffset, newName.c_str());
                methods.erase(methods.find(oldMemberName));
                methods.insert(newName);
            }
            else
            {
                while (methods.find(newName) != methods.end())
                    newName += "_";

                set_member_name(structToChange, memberOffset, newName.c_str());
                methods.erase(methods.find(oldMemberName));
                methods.insert(newName);
            }
        }

        memberOffset = member->eoff;
    }
}

bool UpdateStructure(tid_t tid, ea_t baseAddr)
{
    struc_t* structToChange = get_struc(tid);
    if (!structToChange) 
    {
        msg("Structure not found!\n");
        return false;
    }

    qstring name = get_struc_name(tid);
    ea_t address = 0;
    qsscanf(name.c_str(), "struc_%llx", &address);
    if (baseAddr != address)
        return false;

    qstring vtableName;
    get_ea_name(&vtableName, baseAddr, GN_SHORT | GN_DEMANGLED);
    if (!vtableName.empty())
    {
        std::regex classNameRegex("([a-zA-Z_][a-zA-Z0-9_:]+)::");
        std::smatch match;
        std::string oldName = vtableName.c_str();
        if (std::regex_search(oldName, match, classNameRegex))
        {
            std::string pureTableName = match[1].str() + "Vtbl";
            set_struc_name(tid, pureTableName.c_str());
        }
    }

    ChangeMembers(baseAddr, structToChange);
    return true;
}

struct idb_listener : event_listener_t
{
    tid_t lastStruct = 0;
    virtual ssize_t idaapi on_event(ssize_t notification_code, va_list va) override
    {
        if (notification_code == idb_event::event_code_t::struc_created)
        {
            lastStruct = va_arg(va, tid_t);
            return 0;
        } 
        else if (notification_code == idb_event::event_code_t::make_data)
        {
            ea_t addr = va_arg(va, ea_t);
            flags_t flags = va_arg(va, flags_t);
            tid_t tid = va_arg(va, tid_t);
            asize_t len = va_arg(va, asize_t);
            if (tid == lastStruct)
            {
                if (UpdateStructure(tid, addr))
                    lastStruct = 0;
            }

            return 0;
        }

        return 0;
    }
};

static idb_listener* g_listener;

plugmod_t * idaapi init(void) 
{
    g_listener = new idb_listener();
    
    hook_event_listener(HT_IDB, g_listener, g_listener);

    return PLUGIN_KEEP;
}


void idaapi term(void)
{
    unhook_event_listener(HT_IDB, g_listener);
}



static char comment[] = "IDA struct improvement";
static char help[] = "Demangle names in struct from selection.\n";
static char wanted_name[] = "Demangle names in struct from selection";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE,         // Plugin flags
  init,                // Initialize
  term,                // Terminate. Optional. Called when the plugin is unloaded
  nullptr,                 // Main plugin function. Optional. Unused in this example
  comment,             // Comment. Can be NULL
  help,                // Help. Can be NULL
  wanted_name,         // Plugin name. Can be NULL
  nullptr        // Hotkey for the plugin. Can be NULL
};