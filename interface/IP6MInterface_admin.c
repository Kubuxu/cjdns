/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "interface/IP6MInterface_admin.h"
#include "benc/Int.h"
#include "admin/Admin.h"
#include "crypto/Key.h"
#include "exception/Jmp.h"
#include "memory/Allocator.h"
#include "net/InterfaceController.h"
#include "util/AddrTools.h"
#include "util/events/UDPAddrIface.h"
#include "util/Identity.h"
#include "util/Bits.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

struct Context
{
    struct EventBase* eventBase;
    struct Allocator* alloc;
    struct Log* logger;
    struct Admin* admin;
    struct AddrIface* udpIf;
    struct InterfaceController* ic;
    Identity
};
#if 0
static void beginConnection(Dict* args,
                            void* vcontext,
                            String* txid,
                            struct Allocator* requestAlloc)
{
    struct Context* ctx = Identity_check((struct Context*) vcontext);

    String* password = Dict_getString(args, String_CONST("password"));
    String* login = Dict_getString(args, String_CONST("login"));
    String* publicKey = Dict_getString(args, String_CONST("publicKey"));
    String* macAddress = Dict_getString(args, String_CONST("macAddress"));
    int64_t* interfaceNumber = Dict_getInt(args, String_CONST("interfaceNumber"));
    uint32_t ifNum = (interfaceNumber) ? ((uint32_t) *interfaceNumber) : 0;
    String* peerName = Dict_getString(args, String_CONST("peerName"));
    char* error = "none";

    uint8_t pkBytes[32];

    struct ETHInterface_Sockaddr sockaddr = {
        .generic = {
            .addrLen = ETHInterface_Sockaddr_SIZE
        }
    };

    if (Key_parse(publicKey, pkBytes, NULL)) {
        error = "invalid publicKey";
    } else if (macAddress->len < 17 || AddrTools_parseMac(sockaddr.mac, macAddress->bytes)) {
        error = "invalid macAddress";
    } else {
        int ret = InterfaceController_bootstrapPeer(
            ctx->ic, ifNum, pkBytes, &sockaddr.generic, password, login, peerName, ctx->alloc);

        if (ret == InterfaceController_bootstrapPeer_BAD_IFNUM) {
            error = "invalid interfaceNumber";
        } else if (ret == InterfaceController_bootstrapPeer_BAD_KEY) {
            error = "invalid publicKey";
        } else if (ret == InterfaceController_bootstrapPeer_OUT_OF_SPACE) {
            error = "no more space to register with the switch.";
        } else if (ret) {
            error = "InterfaceController_bootstrapPeer(internal_error)";
        }
    }

    Dict* out = Dict_new(requestAlloc);
    Dict_putString(out, String_CONST("error"), String_new(error, requestAlloc), requestAlloc);
    Admin_sendMessage(out, txid, ctx->admin);
}

#endif

static struct AddrIface* setupLibuvUDP(struct Context* ctx,
                                       struct Sockaddr* addr,
                                       String* txid,
                                       struct Allocator* alloc)
{
    struct UDPAddrIface* udpIf = NULL;
    struct Jmp jmp;
    Jmp_try(jmp) {
        udpIf = UDPAddrIface_new(ctx->eventBase, addr, alloc, &jmp.handler, ctx->logger);
    } Jmp_catch {
        String* errStr = String_CONST(jmp.message);
        Dict out = Dict_CONST(String_CONST("error"), String_OBJ(errStr), NULL);
        Admin_sendMessage(&out, txid, ctx->admin);
        Allocator_free(alloc);
        return NULL;
    }
    return &udpIf->generic;
}

static void newInterface2(struct Context* ctx,
                          struct Sockaddr* addr,
                          String* txid,
                          struct Allocator* requestAlloc)
{
    struct Allocator* const alloc = Allocator_child(ctx->alloc);
    struct AddrIface* ai;
    ai = setupLibuvUDP(ctx, addr, txid, alloc);
    if (!ai) { return; }
    ctx->udpIf = ai;
    struct InterfaceController_Iface* ici =
        InterfaceController_newIface(ctx->ic, String_CONST("IP6M"), alloc);
    Iface_plumb(&ici->addrIf, &ai->iface);

    Dict* out = Dict_new(requestAlloc);
    Dict_putString(out, String_CONST("error"), String_CONST("none"), requestAlloc);
    Dict_putInt(out, String_CONST("interfaceNumber"), ici->ifNum, requestAlloc);
    char* printedAddr = Sockaddr_print(ai->addr, requestAlloc);
    Dict_putString(out,
                   String_CONST("bindAddress"),
                   String_CONST(printedAddr),
                   requestAlloc);

    Admin_sendMessage(out, txid, ctx->admin);
}

static void newInterface(Dict* args,
                        void* vcontext,
                        String* txid,
                        struct Allocator* requestAlloc)
{
    struct Context* const ctx = Identity_check((struct Context*) vcontext);
    String* const bind = Dict_getString(args, String_CONST("bindAddress"));
    struct Allocator* const alloc = Allocator_child(ctx->alloc);
    int bindlen = CString_strlen(bind->bytes);
    char port[] = "64512"; // 0xfc00
    int portlen = CString_strlen(port);
    int len = bindlen + portlen + 2 + 1; // brackets + port + colon
    char *bindAddress = Allocator_calloc(alloc, len + 1, 1); // + null
    sprintf(bindAddress, "[%s]:%s", bind->bytes, port);


    struct Sockaddr_storage addr;
    if (Sockaddr_parse(bindAddress, &addr)) {
        Dict out = Dict_CONST(
            String_CONST("error"), String_OBJ(String_CONST("Failed to parse address")), NULL
        );
        Admin_sendMessage(&out, txid, ctx->admin);
        return;
    }
    newInterface2(ctx, &addr.addr, txid, requestAlloc);
}

static void beacon(Dict* args, void* vcontext, String* txid, struct Allocator* requestAlloc)
{
    int64_t* stateP = Dict_getInt(args, String_CONST("state"));
    int64_t* ifNumP = Dict_getInt(args, String_CONST("interfaceNumber"));
    uint32_t ifNum = (ifNumP) ? ((uint32_t) *ifNumP) : 0;
    uint32_t state = (stateP) ? ((uint32_t) *stateP) : 0xffffffff;
    struct Context* ctx = Identity_check((struct Context*) vcontext);

    char* error = NULL;
    int ret = InterfaceController_beaconState(ctx->ic, ifNum, state);
    if (ret == InterfaceController_beaconState_NO_SUCH_IFACE) {
        error = "invalid interfaceNumber";
    } else if (ret == InterfaceController_beaconState_INVALID_STATE) {
        error = "invalid state";
    } else if (ret) {
        error = "internal";
    }

    if (error) {
        Dict* out = Dict_new(requestAlloc);
        Dict_putString(out, String_CONST("error"), String_CONST(error), requestAlloc);
        Admin_sendMessage(out, txid, ctx->admin);
        return;
    }

    char* stateStr = "disabled";
    if (state == InterfaceController_beaconState_newState_ACCEPT) {
        stateStr = "accepting";
    } else if (state == InterfaceController_beaconState_newState_SEND) {
        stateStr = "sending and accepting";
    }

    Dict out = Dict_CONST(
        String_CONST("error"), String_OBJ(String_CONST("none")), Dict_CONST(
        String_CONST("state"), Int_OBJ(state), Dict_CONST(
        String_CONST("stateName"), String_OBJ(String_CONST(stateStr)), NULL
    )));
    Admin_sendMessage(&out, txid, ctx->admin);
}

static void listDevices(Dict* args, void* vcontext, String* txid, struct Allocator* requestAlloc)
{
    struct Context* ctx = Identity_check((struct Context*) vcontext);

    //TODO(Kubuxu): Implement me. IP6M_listDevices
    Dict* out = Dict_new(requestAlloc);
    Dict_putString(out, String_CONST("error"), String_CONST("WIP"), requestAlloc);
    // Dict_putList(out, String_CONST("devices"), devices, requestAlloc);
    Admin_sendMessage(out, txid, ctx->admin);
}

void IP6MInterface_admin_register(struct EventBase* base,
                                 struct Allocator* alloc,
                                 struct Log* logger,
                                 struct Admin* admin,
                                 struct InterfaceController* ic)
{
    struct Context* ctx = Allocator_clone(alloc, (&(struct Context) {
        .eventBase = base,
        .alloc = alloc,
        .logger = logger,
        .admin = admin,
        .ic = ic
    }));
    Identity_set(ctx);

    Admin_registerFunction("IP6MInterface_new", newInterface, ctx, true,
        ((struct Admin_FunctionArg[]) {
            { .name = "bindAddress", .required = 1, .type = "String" },
            { .name = "scope", .required = 0, .type = "Int" }
        }), admin);

    /*Admin_registerFunction("IP6MInterface_beginConnection",
        beginConnection, ctx, true, ((struct Admin_FunctionArg[]) {
            { .name = "interfaceNumber", .required = 0, .type = "Int" },
            { .name = "password", .required = 0, .type = "String" },
            { .name = "publicKey", .required = 1, .type = "String" },
            { .name = "address", .required = 1, .type = "String" },
            { .name = "login", .required = 0, .type = "String" }
        }), admin);
    */
    Admin_registerFunction("IP6MInterface_beacon", beacon, ctx, true,
        ((struct Admin_FunctionArg[]) {
            { .name = "interfaceNumber", .required = 0, .type = "Int" },
            { .name = "state", .required = 0, .type = "Int" }
        }), admin);

    Admin_registerFunction("IP6MInterface_listDevices", listDevices, ctx, true, NULL, admin);
}
