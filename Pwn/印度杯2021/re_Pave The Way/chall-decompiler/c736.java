class c736 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "p";
      System.out.print(".");
      Thread.sleep(3600000L);
      c294.pave(var0);
   }
}
