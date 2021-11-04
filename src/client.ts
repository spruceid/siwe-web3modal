// TODO: Figure out how to get types from this lib:
import { ethers } from "ethers";
import EventEmitter from "events";
import Cookies from "js-cookie";
import { SignatureType, SiweMessage } from "siwe";
import type { ICoreOptions } from "web3modal";
import Web3Modal from "web3modal";

export interface SiweSession {
  message: SiweMessage;
  signature: string;
  address: string;
  ens?: string;
  ensAvatar?: string;
}

export interface SessionOpts {
  domain: string;
  uri: string;
  useENS: boolean;
  version: string;
  // Defaults to 48 hours.
  expiration?: number;
  statement?: string;
}

export interface ClientOpts {
  session: SessionOpts;
  modal?: Partial<ICoreOptions>;
  currentSession?: SiweSession;
}

export class Client extends EventEmitter {
  provider: ethers.providers.JsonRpcProvider;
  modalOpts: Partial<ICoreOptions>;
  sessionOpts: SessionOpts;
  session: SiweSession;
  web3Modal: Web3Modal;

  constructor(opts: ClientOpts) {
    super();

    this.modalOpts = opts?.modal || {};
    this.session = opts?.currentSession;
    this.sessionOpts = opts.session;

    const sanity =
      this.sessionOpts?.expiration &&
      typeof this.sessionOpts.expiration === "number" &&
      this.sessionOpts.expiration > 0;

    if (!sanity) {
      // Default to 48 hours.
      this.sessionOpts.expiration = 2 * 24 * 60 * 60 * 1000;
    }

    const sessionCookie = Cookies.get("siwe");
    if (sessionCookie) {
      const { message, signature, address, ens, ensAvatar } =
        JSON.parse(sessionCookie);
      this.session = {
        message: new SiweMessage(message),
        signature,
        address,
        ens,
        ensAvatar,
      };
    }

    this.web3Modal = new Web3Modal({ ...this.modalOpts, cacheProvider: true });

    this.web3Modal.on("accountsChanged", (e) =>
      this.emit("accountsChanged", e)
    );
    this.web3Modal.on("chainChanged", (e) => this.emit("chainChanged", e));
    this.web3Modal.on("connect", (e) => this.emit("connect", e));
    this.web3Modal.on("disconnect", (e) => this.emit("disconnect", e));
  }

  async signOut() {
    this.provider = null;
    this.session = null;
    this.web3Modal.clearCachedProvider();

    Cookies.remove("siwe");
    this.emit("signOut");
  }

  async signIn(nonce?: string): Promise<SiweSession> {
    return new Promise(async (resolve, reject) => {
      try {
        await this.initializeProvider();

        this.emit("modalClosed");

        // Get list of accounts of the connected wallet
        const accounts = await this.provider.listAccounts();

        // MetaMask does not give you all accounts, only the selected account
        const address = accounts[0]?.toLowerCase();
        if (!address) {
          throw new Error("Address not found");
        }
        const ens = await this.provider.lookupAddress(address);

        const ensAvatar = await this.provider.getAvatar(address);

        const expirationTime = new Date(
          new Date().getTime() + this.sessionOpts.expiration
        );

        const message = new SiweMessage({
          domain: this.sessionOpts.domain,
          address: address,
          expirationTime: expirationTime.toISOString(),
          uri: this.sessionOpts.uri,
          version: this.sessionOpts.version,
          statement: this.sessionOpts.statement,
          type: SignatureType.PERSONAL_SIGNATURE,
          nonce,
        }).signMessage();

        const signature = await this.provider.getSigner().signMessage(message);

        const session: SiweSession = {
          message: new SiweMessage(message),
          signature,
          address,
          ens,
          ensAvatar,
        };
        Cookies.set("siwe", JSON.stringify(session), {
          expires: expirationTime,
        });

        this.emit("signIn", session);

        resolve(session);
      } catch (e) {
        this.signOut();
        reject(e);
      }
    });
  }

  async valitate() {
    await this.initializeProvider();

    try {
      this.emit("validate", await this.session.message.validate(this.provider));
    } catch (e) {
      this.emit("validate", e);
    }
  }

  async initializeProvider(): Promise<ethers.providers.JsonRpcProvider> {
    return new Promise<ethers.providers.JsonRpcProvider>((resolve, reject) => {
      if (!this.provider) {
        return this.web3Modal
          .connect()
          .then((provider) => {
            this.provider = new ethers.providers.Web3Provider(provider);
            resolve(this.provider);
          })
          .catch(reject);
      } else {
        resolve(this.provider);
      }
    });
  }
}
