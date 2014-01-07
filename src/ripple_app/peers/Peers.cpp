//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012, 2013 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include "PeerDoor.h"

class PeersLog;
template <> char const* LogPartition::getPartitionName <PeersLog> () { return "Peers"; }

class PeerFinderLog;
template <> char const* LogPartition::getPartitionName <PeerFinderLog> () { return "PeerFinder"; }

class NameResolverLog;
template <> char const* LogPartition::getPartitionName <NameResolverLog> () { return "NameResolver"; }

/** Calls a function during static initialization. */
struct static_call
{
    // Function must be callable as
    //      void f (void) const
    //
    template <class Function>
    static_call (Function const& f)
    {
        f ();
    }
};

static static_call init_PeerFinderLog (&LogPartition::get <PeerFinderLog>);
static static_call init_NameResolverLog (&LogPartition::get <NameResolverLog>);

//------------------------------------------------------------------------------
/** A functor to visit all active peers and retrieve their JSON data */
struct get_peer_json
{
    typedef Json::Value return_type;

    Json::Value json;

    get_peer_json ()
    { }

    void operator() (Peer::ref peer)
    {
        json.append (peer->json ());
    }

    Json::Value operator() ()
    {
        return json;
    }
};

//------------------------------------------------------------------------------

class PeersImp
    : public Peers
    , public PeerFinder::Callback
    , public LeakChecked <PeersImp>
{    
public:
    typedef boost::unordered_map <IPAddress, Peer::pointer> PeerByIP;

    typedef boost::unordered_map <
        RippleAddress, Peer::pointer> PeerByPublicKey;

    typedef boost::unordered_map <
        Peer::ShortId, Peer::pointer> PeerByShortId;

    typedef RippleRecursiveMutex LockType;

    typedef LockType::ScopedLockType ScopedLockType;

    Journal m_journal;
    Resource::Manager& m_resourceManager;

    std::unique_ptr <PeerFinder::Manager> m_peerFinder;

    boost::asio::io_service& m_io_service;
    boost::asio::ssl::context& m_ssl_context;

    struct State
    {
        /** Tracks peers by their IP address and port */
        PeerByIP ipMap;

        /** Tracks peers by their public key */
        PeerByPublicKey publicKeyMap;

        /** Tracks peers by their session ID */
        PeerByShortId shortIdMap;

        /** Tracks all instances of peer objects */
        List <Peer> list;
    };

    typedef SharedData <State> SharedState;

    SharedState m_state;

    /** The peer door for regular SSL connections */
    std::unique_ptr <PeerDoor> m_doorDirect;

    /** The peer door for proxy connections */
    std::unique_ptr <PeerDoor> m_doorProxy;

    /** The resolver we use for peer hostnames */
    Resolver& m_resolver;

    /** Monotically increasing identifiers for peers */
    Atomic <Peer::ShortId> m_nextShortId;

    //--------------------------------------------------------------------------
    //
    // Peers
    //
    //--------------------------------------------------------------------------

    PeersImp (Stoppable& parent,
        Resource::Manager& resourceManager,
            SiteFiles::Manager& siteFiles,
                Resolver& resolver,
                    boost::asio::io_service& io_service,
                        boost::asio::ssl::context& ssl_context)
        : Peers (parent)
        , m_journal (LogPartition::getJournal <PeersLog> ())
        , m_resourceManager (resourceManager)
        , m_peerFinder (add (PeerFinder::Manager::New (
            *this,
            siteFiles,
            *this,
            LogPartition::getJournal <PeerFinderLog> ())))
        , m_io_service (io_service)
        , m_ssl_context (ssl_context)
        , m_resolver (resolver)
    {

    }

    void accept (
        bool proxyHandshake,
        boost::shared_ptr <NativeSocketType> const& socket)
    {
        Peer::accept (
            socket,
            *this,
            m_resourceManager,
            *m_peerFinder,
            m_ssl_context,
            proxyHandshake);
    }

    void connect (IP::Endpoint const& address)
    {
        Peer::connect (
            address,
            m_io_service,
            *this,
            m_resourceManager,
            *m_peerFinder,
            m_ssl_context);
    }

    //--------------------------------------------------------------------------
    void peerCreated (Peer* peer)
    {
        SharedState::Access state (m_state);
        state->list.push_back (*peer);
    }

    void peerDestroyed (Peer* peer)
    {
        SharedState::Access state (m_state);
        state->list.erase (state->list.iterator_to (*peer));
    }

    //--------------------------------------------------------------------------
    //
    // PeerFinder::Callback
    //
    //--------------------------------------------------------------------------

    void connectPeers (std::vector <IPAddress> const& list)
    {
        for (std::vector <IPAddress>::const_iterator iter (list.begin());
            iter != list.end(); ++iter)
            connect (*iter);
    }

    void disconnectPeer (IPAddress const& address, bool graceful)
    {
        m_journal.trace <<
            "disconnectPeer (" << address <<
            ", " << graceful << ")";

        SharedState::Access state (m_state);

        PeerByIP::iterator const it (state->ipMap.find (address));

        if (it != state->ipMap.end ())
            it->second->detach ("disc", false);
    }

    void activatePeer (IPAddress const& remote_address)
    {
        m_journal.trace <<
            "activatePeer (" << remote_address << ")";

        SharedState::Access state (m_state);

        PeerByIP::iterator const it (state->ipMap.find (remote_address));

        if (it != state->ipMap.end ())
            it->second->activate();
    }

    void sendEndpoints (IPAddress const& remote_address,
        std::vector <PeerFinder::Endpoint> const& endpoints)
    {
        bassert (! endpoints.empty());
        typedef std::vector <PeerFinder::Endpoint> List;
        protocol::TMEndpoints tm;
        for (List::const_iterator iter (endpoints.begin());
            iter != endpoints.end(); ++iter)
        {
            PeerFinder::Endpoint const& ep (*iter);
            protocol::TMEndpoint& tme (*tm.add_endpoints());
            if (ep.address.is_v4())
                tme.mutable_ipv4()->set_ipv4(
                    toNetworkByteOrder (ep.address.to_v4().value));
            else
                tme.mutable_ipv4()->set_ipv4(0);
            tme.mutable_ipv4()->set_ipv4port (ep.address.port());

            tme.set_hops (ep.hops);
            tme.set_features (ep.features);

            // DEPRECATED these are unused and should be removed!
            tme.set_slots (0);
            tme.set_maxslots (0);
            tme.set_uptimeseconds (0);
        }

        PackedMessage::pointer msg (
            boost::make_shared <PackedMessage> (
                tm, protocol::mtENDPOINTS));

        SharedState::Access state (m_state);
        PeerByIP::iterator const iter (state->ipMap.find (remote_address));
        // Address must exist!
        check_postcondition (iter != state->ipMap.end());
        Peer::pointer peer (iter->second);
        // VFALCO TODO Why are we checking isConnected? That should not be needed
        if (peer->isConnected())
            peer->sendPacket (msg, false);
    }

    //--------------------------------------------------------------------------
    //
    // Stoppable
    //
    //--------------------------------------------------------------------------

    void onPrepare ()
    {
        PeerFinder::Config config;

        config.maxPeers = getConfig ().PEERS_MAX;

        config.outPeers = config.calcOutPeers();

        config.wantIncoming =
            (! getConfig ().PEER_PRIVATE) &&
            (getConfig().peerListeningPort != 0);

        // if it's a private peer or we are running as standalone
        // automatic connections would defeat the purpose.
        config.autoConnect =
            !getConfig().RUN_STANDALONE &&
            !getConfig().PEER_PRIVATE;

        config.listeningPort = getConfig().peerListeningPort;

        config.features = "";

        // Enforce business rules
        config.applyTuning ();

        m_peerFinder->setConfig (config);

        // Add the static IPs from the rippled.cfg file
        m_peerFinder->addFallbackStrings ("rippled.cfg", getConfig().IPS);

        // Add the ips_fixed from the rippled.cfg file
        if (! getConfig ().RUN_STANDALONE && !getConfig ().IPS_FIXED.empty ())
        {
            struct resolve_fixed_peers
            {
                PeerFinder::Manager* m_peerFinder;

                resolve_fixed_peers (PeerFinder::Manager* peerFinder)
                    : m_peerFinder (peerFinder)
                { }

                void operator()(std::string const& name,
                    std::vector <IPAddress> const& address)
                {
                    if (!address.empty())
                        m_peerFinder->addFixedPeer (name, address);
                }
            };

            m_resolver.resolve (getConfig ().IPS_FIXED,
                resolve_fixed_peers (m_peerFinder.get ()));
        }

        // Configure the peer doors, which allow the server to accept incoming
        // peer connections:
        // Create the listening sockets for peers
        //
        m_doorDirect.reset (PeerDoor::New (
            PeerDoor::sslRequired,
            *this,
            getConfig ().PEER_IP,
            getConfig ().peerListeningPort,
            m_io_service));

        if (getConfig ().peerPROXYListeningPort != 0)
        {
            m_doorProxy.reset (PeerDoor::New (
                PeerDoor::sslAndPROXYRequired,
                *this,
                getConfig ().PEER_IP,
                getConfig ().peerPROXYListeningPort,
                m_io_service));
        }
    }

    void onStart ()
    {
    }

    void onStop ()
    {
        m_resolver.stop_async();
    }

    void onChildrenStopped ()
    {
        m_resolver.stop ();

        // VFALCO TODO Clean this up and do it right, based on sockets
        stopped();
    }

    //--------------------------------------------------------------------------
    //
    // PropertyStream
    //
    //--------------------------------------------------------------------------

    void onWrite (PropertyStream& stream)
    {
    }

    //--------------------------------------------------------------------------
    /** A peer has connected successfully
        This is called after the peer handshake has been completed and during
        peer activation. At this point, the peer address and the public key
        are known.
    */
    void onPeerActivated (Peer::ref peer)
    {
        // First assign this peer a new short ID
        peer->setShortId(++m_nextShortId);

        SharedState::Access state (m_state);

        // Now track this peer
        std::pair<PeerByShortId::iterator, bool> idResult(
            state->shortIdMap.emplace (
                boost::unordered::piecewise_construct,
                boost::make_tuple (peer->getShortId()),
                boost::make_tuple (peer)));
        check_postcondition(idResult.second);

        std::pair<PeerByPublicKey::iterator, bool> keyResult(
            state->publicKeyMap.emplace (
                boost::unordered::piecewise_construct,
                boost::make_tuple (peer->getNodePublic()),
                boost::make_tuple (peer)));
        check_postcondition(keyResult.second);

        m_journal.debug << 
            "activated " << peer->getRemoteAddress() <<
            " (" << peer->getShortId() << 
            ":" << RipplePublicKey(peer->getNodePublic()) << ")";

        // We just accepted this peer so we have non-zero active peers
        check_postcondition(size() != 0);
    }

    /** A peer is being disconnected
        This is called during the disconnection of a known, activated peer. It
        will not be called for outbound peer connections that don't succeed or
        for connections of peers that are dropped prior to being activated.
    */
    void onPeerDisconnect (Peer::ref peer)
    {
        SharedState::Access state (m_state);
        state->shortIdMap.erase (peer->getShortId ());
        state->publicKeyMap.erase (peer->getNodePublic ());
    }

    /** The number of active peers on the network
        Active peers are only those peers that have completed the handshake
        and are running the Ripple protocol.
    */
    std::size_t size ()
    {
        SharedState::Access state (m_state);
        return state->publicKeyMap.size ();
    }

    // Returns information on verified peers.
    Json::Value json ()
    {
        return foreach (get_peer_json());
    }

    Peers::PeerSequence getActivePeers ()
    {
        Peers::PeerSequence ret;

        SharedState::Access state (m_state);

        ret.reserve (state->publicKeyMap.size ());

        BOOST_FOREACH (PeerByPublicKey::value_type const& pair, state->publicKeyMap)
        {
            assert (!!pair.second);
            ret.push_back (pair.second);
        }

        return ret;
    }

    Peer::pointer findPeerByShortID (Peer::ShortId const& id)
    {
        SharedState::Access state (m_state);
        PeerByShortId::iterator const iter (
            state->shortIdMap.find (id));
        if (iter != state->shortIdMap.end ())
            iter->second;
        return Peer::pointer();
    }

    // TODO NIKB Rename these two functions. It's not immediately clear
    //           what they do: create a tracking entry for a peer by
    //           the peer's remote IP.
    /** Start tracking a peer */
    void addPeer (Peer::Ptr const& peer)
    {
        SharedState::Access state (m_state);

        std::pair<PeerByIP::iterator, bool> keyResult(
            state->ipMap.emplace (
                boost::unordered::piecewise_construct,
                boost::make_tuple (peer->getRemoteAddress()),
                boost::make_tuple (peer)));

        check_postcondition(keyResult.second);
    }

    /** Stop tracking a peer */
    void removePeer (Peer::Ptr const& peer)
    {
        SharedState::Access state (m_state);
        state->ipMap.erase (peer->getRemoteAddress());
    }

    /** Retrieves a reference to the instance of the PeerFinder

        @note This reference is valid for the lifetime of the Peers singleton,
              which should be enough since it's only used by instances of Peer.
    */
    PeerFinder::Manager &getPeerFinder ()
    {
        return *m_peerFinder;
    }
};

//------------------------------------------------------------------------------

Peers::~Peers ()
{
}

Peers* Peers::New (Stoppable& parent,
    Resource::Manager& resourceManager,
        SiteFiles::Manager& siteFiles,
            Resolver& resolver,
                boost::asio::io_service& io_service,
                    boost::asio::ssl::context& ssl_context)
{
    return new PeersImp (parent, resourceManager, siteFiles, 
        resolver, io_service, ssl_context);
}

