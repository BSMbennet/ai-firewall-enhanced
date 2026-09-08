import { createContext, useContext, useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const AuthContext = createContext(null)
export const useAuth = () => { const context=useContext(AuthContext); if(!context) throw new Error('useAuth must be used within an AuthProvider'); return context }

export const AuthProvider = ({ children }) => {
 const [user,setUser]=useState(null),[session,setSession]=useState(null),[loading,setLoading]=useState(true)
 useEffect(()=>{let mounted=true; const init=async()=>{const {data,error}=await supabase.auth.getSession();if(!mounted)return;if(error)console.error('Failed to restore Supabase session',error);setSession(data.session??null);setUser(data.session?.user??null);setLoading(false)};init();const {data:subscription}=supabase.auth.onAuthStateChange((_event,next)=>{if(!mounted)return;setSession(next??null);setUser(next?.user??null);setLoading(false)});return()=>{mounted=false;subscription.subscription.unsubscribe()}},[])
 const signIn=async(email,password)=>{const {data,error}=await supabase.auth.signInWithPassword({email,password});if(error)throw error;setSession(data.session);setUser(data.user);return data}
 const signInWithProvider=async(provider)=>{const {data,error}=await supabase.auth.signInWithOAuth({provider,options:{redirectTo:window.location.origin}});if(error)throw error;return data}
 const signUp=async(email,password,metadata={})=>{const {data,error}=await supabase.auth.signUp({email,password,options:{data:metadata}});if(error)throw error;return data}
 const signOut=async()=>{const {error}=await supabase.auth.signOut();if(error)throw error;setSession(null);setUser(null)}
 return <AuthContext.Provider value={{user,session,loading,signIn,signInWithProvider,signUp,signOut}}>{children}</AuthContext.Provider>
}
