import { Client, LocalAuth, MessageMedia, Poll, Chat } from 'whatsapp-web.js';
import qrcode from 'qrcode-terminal';
import crypto from 'crypto';
import fs from 'fs';
import { BroadcastPayload, tryRecordDigest, clampPinDuration } from './db.js';
import { log } from './logger.js';

function randomBetween(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function computeDigest(payload: BroadcastPayload): string {
  const parts: string[] = [];
  if (payload.text) parts.push(payload.text);
  if (payload.originalName) parts.push(payload.originalName);
  if (payload.pollQuestion) parts.push(payload.pollQuestion);
  if (payload.pollOptions) parts.push(payload.pollOptions.join('|'));
  return crypto.createHash('sha256').update(parts.join('::')).digest('base64');
}

export class AnnouncementBot {
  private client: Client;
  private groupAId: string;
  private groupBId: string;
  private ready = false;
  private killSwitchActive = false;
  private reconnecting = false;
  private groupsValid: boolean | null = null;
  private groupAName = '';
  private groupBName = '';
  private shuttingDown = false;

  constructor(groupAId: string, groupBId: string) {
    this.groupAId = groupAId.trim();
    this.groupBId = groupBId.trim();

    this.client = new Client({
      authStrategy: new LocalAuth({ dataPath: './.wwebjs_auth' }),
      puppeteer: {
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--no-zygote',
          '--disable-extensions',
          '--disable-background-networking',
          '--disable-sync',
          '--disable-translate',
          '--mute-audio',
          '--hide-scrollbars',
          '--metrics-recording-only',
          '--no-first-run',
          '--safebrowsing-disable-auto-update',
        ],
      },
    });

    this.client.on('qr', (qr) => {
      log.info('Scan this QR code with WhatsApp (Linked Devices)');
      qrcode.generate(qr, { small: true });
    });

    this.client.on('ready', async () => {
      this.ready = true;
      this.reconnecting = false;
      log.info('WhatsApp client is ready');
      await this.printGroupList();
      await this.validateGroups();
    });

    this.client.on('authenticated', () => {
      log.info('WhatsApp authenticated successfully');
    });

    this.client.on('auth_failure', (msg) => {
      log.error('Authentication failure', msg);
    });

    this.client.on('disconnected', (reason) => {
      this.ready = false;
      this.groupsValid = null;
      log.warn('WhatsApp disconnected', reason);
      if (!this.shuttingDown) {
        this.scheduleReconnect();
      }
    });
  }

  private scheduleReconnect(): void {
    if (this.reconnecting || this.shuttingDown) return;
    this.reconnecting = true;
    const delay = randomBetween(5000, 15000);
    log.info(`Scheduling reconnect in ${delay}ms`);
    setTimeout(async () => {
      if (this.shuttingDown) return;
      try {
        log.info('Attempting WhatsApp re-initialize…');
        await this.client.initialize();
      } catch (err) {
        log.error('Reconnect failed', err instanceof Error ? err.message : String(err));
        this.reconnecting = false;
        this.scheduleReconnect();
      }
    }, delay);
  }

  async start(): Promise<void> {
    await this.client.initialize();
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    try {
      await this.client.destroy();
      log.info('WhatsApp client destroyed');
    } catch (err) {
      log.warn('Client destroy error', err instanceof Error ? err.message : String(err));
    }
  }

  isReady(): boolean {
    return this.ready;
  }

  areGroupsConfigured(): boolean {
    return !!(this.groupAId && this.groupBId);
  }

  areGroupsValid(): boolean | null {
    return this.groupsValid;
  }

  getGroupLabels(): { a: string; b: string } {
    return {
      a: this.groupAName || this.groupAId || '(not set)',
      b: this.groupBName || this.groupBId || '(not set)',
    };
  }

  setKillSwitch(active: boolean): void {
    this.killSwitchActive = active;
    log.info(`Kill switch ${active ? 'ACTIVATED' : 'deactivated'}`);
  }

  isKillSwitchActive(): boolean {
    return this.killSwitchActive;
  }

  private async printGroupList(): Promise<void> {
    try {
      const chats = await this.client.getChats();
      const groups = chats.filter((c) => c.isGroup);
      log.info('--- Group Discovery List ---');
      for (const g of groups) {
        log.info(`  ${g.name} => ${g.id._serialized}`);
      }
      log.info('Copy group IDs into .env as GROUP_A_ID and GROUP_B_ID');
    } catch (err) {
      log.error('Failed to list groups', err instanceof Error ? err.message : String(err));
    }
  }

  private async validateGroups(): Promise<void> {
    if (!this.areGroupsConfigured()) {
      this.groupsValid = false;
      log.warn('GROUP_A_ID and/or GROUP_B_ID not set in .env — broadcasts disabled until configured');
      return;
    }
    try {
      const chatA = await this.client.getChatById(this.groupAId);
      const chatB = await this.client.getChatById(this.groupBId);
      if (!chatA || !chatB) {
        this.groupsValid = false;
        log.warn('One or both configured group IDs were not found in the account chat list');
        return;
      }
      this.groupAName = chatA.name || this.groupAId;
      this.groupBName = chatB.name || this.groupBId;
      this.groupsValid = true;
      log.info(`Groups validated: A="${this.groupAName}" B="${this.groupBName}"`);
    } catch (err) {
      this.groupsValid = false;
      log.warn('Group validation failed', err instanceof Error ? err.message : String(err));
    }
  }

  private async simulatePresence(chat: Chat, isVoice: boolean): Promise<void> {
    try {
      if (isVoice) {
        await chat.sendStateRecording();
      } else {
        await chat.sendStateTyping();
      }
      await sleep(randomBetween(1800, 3200));
      await chat.clearState();
    } catch (err) {
      log.warn('Presence simulation failed (non-fatal)', err instanceof Error ? err.message : String(err));
    }
  }

  private async sendToGroup(
    groupId: string,
    payload: BroadcastPayload,
    type: 'TEXT' | 'MEDIA' | 'POLL'
  ): Promise<void> {
    const chat = await this.client.getChatById(groupId);
    if (!chat) {
      throw new Error(`Chat not found for group ID: ${groupId}`);
    }

    const isVoice = !!(payload.sendAsVoice && payload.filePath);
    await this.simulatePresence(chat, isVoice);

    let sentMessage;

    if (type === 'POLL' && payload.pollQuestion && payload.pollOptions) {
      const poll = new Poll(payload.pollQuestion, payload.pollOptions, {
        allowMultipleAnswers: !!payload.allowMultipleAnswers,
        messageSecret: undefined,
      });
      sentMessage = await chat.sendMessage(poll);
    } else if (type === 'MEDIA' && payload.filePath) {
      if (!fs.existsSync(payload.filePath)) {
        throw new Error(`Media file not found: ${payload.filePath}`);
      }
      const media = MessageMedia.fromFilePath(payload.filePath);
      if (payload.originalName) {
        media.filename = payload.originalName;
      }
      const options: { caption?: string; sendAudioAsVoice?: boolean } = {};
      if (payload.text) options.caption = payload.text;
      if (payload.sendAsVoice) options.sendAudioAsVoice = true;
      sentMessage = await chat.sendMessage(media, options);
    } else {
      const text = payload.text ?? '';
      if (!text.trim()) {
        throw new Error('Empty text payload');
      }
      sentMessage = await chat.sendMessage(text);
    }

    const pinSec = clampPinDuration(payload.pinDuration ?? 0);
    if (pinSec && sentMessage) {
      try {
        await sentMessage.pin(pinSec);
      } catch (err) {
        log.warn('Pin failed (non-fatal)', err instanceof Error ? err.message : String(err));
      }
    }
  }

  async broadcast(
    type: 'TEXT' | 'MEDIA' | 'POLL',
    payload: BroadcastPayload
  ): Promise<{ success: boolean; blocked?: boolean; error?: string }> {
    if (this.killSwitchActive) {
      return { success: false, blocked: true, error: 'Kill switch is active' };
    }

    if (!this.areGroupsConfigured()) {
      return { success: false, error: 'GROUP_A_ID / GROUP_B_ID not configured' };
    }

    if (!this.ready) {
      return { success: false, error: 'WhatsApp client not ready' };
    }

    const digest = computeDigest(payload);
    if (!tryRecordDigest(digest)) {
      return { success: false, error: 'Duplicate broadcast detected within the last 24h' };
    }

    // Normalize pin on the way out
    const normalized: BroadcastPayload = {
      ...payload,
      pinDuration: clampPinDuration(payload.pinDuration ?? 0),
    };

    try {
      await this.sendToGroup(this.groupAId, normalized, type);
      await sleep(randomBetween(3500, 6500));
      await this.sendToGroup(this.groupBId, normalized, type);
      return { success: true };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      log.error('Broadcast failed', message);
      return { success: false, error: message };
    }
  }
}
