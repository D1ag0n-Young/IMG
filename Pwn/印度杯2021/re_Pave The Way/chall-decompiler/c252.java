class c252 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "D";
      System.out.print(".");
      Thread.sleep(3600000L);
      c204.pave(var0);
   }
}
