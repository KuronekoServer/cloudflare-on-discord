import type { Channel, Message } from "@cloudcord/contracts";
import { create } from "zustand";

export interface GuildSummary {
  id: string;
  ownerId: string;
  name: string;
  description: string | null;
}
interface AppState {
  guilds: GuildSummary[];
  channels: Channel[];
  messages: Message[];
  activeGuildId: string | null;
  activeChannelId: string | null;
  setGuilds: (guilds: GuildSummary[]) => void;
  selectGuild: (id: string) => void;
  setChannels: (channels: Channel[]) => void;
  selectChannel: (id: string) => void;
  setMessages: (messages: Message[]) => void;
  upsertMessage: (message: Message) => void;
  removeMessage: (id: string) => void;
}

export const useAppStore = create<AppState>((set) => ({
  guilds: [],
  channels: [],
  messages: [],
  activeGuildId: null,
  activeChannelId: null,
  setGuilds: (guilds) =>
    set((state) => ({
      guilds,
      activeGuildId: state.activeGuildId ?? guilds[0]?.id ?? null,
    })),
  selectGuild: (id) =>
    set({
      activeGuildId: id,
      activeChannelId: null,
      channels: [],
      messages: [],
    }),
  setChannels: (channels) =>
    set((state) => ({
      channels,
      activeChannelId:
        state.activeChannelId ??
        channels.find((channel) => channel.type === "GUILD_TEXT")?.id ??
        channels[0]?.id ??
        null,
    })),
  selectChannel: (id) => set({ activeChannelId: id, messages: [] }),
  setMessages: (messages) => set({ messages }),
  upsertMessage: (message) =>
    set((state) =>
      state.messages.some((item) => item.id === message.id)
        ? {
            messages: state.messages.map((item) =>
              item.id === message.id ? message : item,
            ),
          }
        : { messages: [...state.messages, message] },
    ),
  removeMessage: (id) =>
    set((state) => ({
      messages: state.messages.filter((message) => message.id !== id),
    })),
}));
