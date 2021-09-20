class c325 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "p";
      System.out.print(".");
      Thread.sleep(3600000L);
      c890.pave(var0);
   }
}
