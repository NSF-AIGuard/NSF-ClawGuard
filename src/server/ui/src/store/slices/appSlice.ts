import { createSlice, PayloadAction } from '@reduxjs/toolkit'

export interface AppState {
    isLoading: boolean
    theme: 'light' | 'dark'
    sidebarCollapsed: boolean
}

const initialState: AppState = {
    isLoading: false,
    theme: 'light',
    sidebarCollapsed: false,
}

export const appSlice = createSlice({
    name: 'app',
    initialState,
    reducers: {
        setLoading: (state, action: PayloadAction<boolean>) => {
            state.isLoading = action.payload
        },
        setTheme: (state, action: PayloadAction<'light' | 'dark'>) => {
            state.theme = action.payload
        },
        toggleSidebar: (state) => {
            state.sidebarCollapsed = !state.sidebarCollapsed
        },
    },
})

export const { setLoading, setTheme, toggleSidebar } = appSlice.actions

export default appSlice.reducer
